// Copyright (C) 2016 Colin Nicholson
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

package dynamodbstore

import (
	"bytes"
	"encoding/base32"
	"encoding/gob"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/dynamodb"
)

var sessionExpire = 86400 * 30
var expireScanInterval = time.Hour * 24

// SessionSerializer provides an interface hook for alternative serializers
type SessionSerializer interface {
	Deserialize(d []byte, ss *sessions.Session) error
	Serialize(ss *sessions.Session) ([]byte, error)
}

// GobSerializer uses gob package to encode the session map
type GobSerializer struct{}

// Serialize using gob
func (s GobSerializer) Serialize(ss *sessions.Session) ([]byte, error) {
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	err := enc.Encode(ss.Values)
	if err == nil {
		return buf.Bytes(), nil
	}
	return nil, err
}

// Deserialize back to map[interface{}]interface{}
func (s GobSerializer) Deserialize(d []byte, ss *sessions.Session) error {
	dec := gob.NewDecoder(bytes.NewBuffer(d))
	return dec.Decode(&ss.Values)
}

// DynamoDBStore stores sessions in a DynamoDB table.
type DynamoDBStore struct {
	Db            *dynamodb.DynamoDB
	Table         string
	Codecs        []securecookie.Codec
	Options       *sessions.Options // default configuration
	DefaultMaxAge int               // default TTL for a MaxAge == 0 session
	serializer    SessionSerializer
}

// SetSerializer sets the serializer
func (s *DynamoDBStore) SetSerializer(ss SessionSerializer) {
	s.serializer = ss
}

// SetMaxAge restricts the maximum age, in seconds, of the session record
// both in database and a browser. This is to change session storage configuration.
// If you want just to remove session use your session `s` object and change it's
// `Options.MaxAge` to -1, as specified in
//    http://godoc.org/github.com/gorilla/sessions#Options
//
// Default is the one provided by this package value - `sessionExpire`.
// Set it to 0 for no restriction.
// Because we use `MaxAge` also in SecureCookie crypting algorithm you should
// use this function to change `MaxAge` value.
func (s *DynamoDBStore) SetMaxAge(v int) {
	var c *securecookie.SecureCookie
	var ok bool
	s.Options.MaxAge = v
	for i := range s.Codecs {
		if c, ok = s.Codecs[i].(*securecookie.SecureCookie); ok {
			c.MaxAge(v)
		} else {
			fmt.Printf("Can't change MaxAge on codec %v\n", s.Codecs[i])
		}
	}
}

// NewDynamoDBStore returns a new DynamoDBStore.
// sessionCookieExpireTime controls how long a session will live in the database when it is set to 0 seconds expire time aka session cookie
// sessionTableName is name of dynamodb table to use - is created if it does not exist. If created, readCapacityUnits and writeCapacityUnits are used
func NewDynamoDBStore(db *dynamodb.DynamoDB, sessionCookieExpireTime int, sessionTableName string, readCapacityUnits int64, writeCapacityUnits int64, keyPairs ...[]byte) (*DynamoDBStore, error) {

	if err := tryCreateTable(db, sessionTableName, readCapacityUnits, writeCapacityUnits); err != nil {
		return nil, err
	}

	newDynamoDBStore := &DynamoDBStore{
		Db:     db,
		Table:  sessionTableName,
		Codecs: securecookie.CodecsFromPairs(keyPairs...),
		Options: &sessions.Options{
			Path:   "/",
			MaxAge: sessionExpire,
		},
		DefaultMaxAge: sessionCookieExpireTime,
		serializer:    GobSerializer{},
	}

	go newDynamoDBStore.runBackgroundExpiration()

	return newDynamoDBStore, nil

}

// make sure session table exists
func tryCreateTable(db *dynamodb.DynamoDB, sessionTableName string, readCapacityUnits, writeCapacityUnits int64) error {

	describeTableInput := &dynamodb.DescribeTableInput{TableName: aws.String(sessionTableName)}
	if _, err := db.DescribeTable(describeTableInput); err != nil {
		awserr := err.(awserr.Error)
		if awserr.Code() == "ResourceNotFoundException" {
			// table does not exist - create now

			params := &dynamodb.CreateTableInput{
				TableName: aws.String(sessionTableName),
				AttributeDefinitions: []*dynamodb.AttributeDefinition{ // Required
					{ // Required
						AttributeName: aws.String("id"),
						AttributeType: aws.String("S"), // Required
					},
				},
				KeySchema: []*dynamodb.KeySchemaElement{ // Required
					{ // Required
						AttributeName: aws.String("id"),
						KeyType:       aws.String("HASH"), // Required
					},
				},
				ProvisionedThroughput: &dynamodb.ProvisionedThroughput{
					ReadCapacityUnits:  aws.Int64(readCapacityUnits),
					WriteCapacityUnits: aws.Int64(writeCapacityUnits),
				},
			}

			if _, err := db.CreateTable(params); err != nil {
				return err
			}

		} else {
			return err
		}
	}

	return nil

}

// Get returns a session for the given name after adding it to the registry.
//
// See gorilla/sessions FilesystemStore.Get().
func (s *DynamoDBStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(s, name)
}

// New returns a session for the given name without adding it to the registry.
//
// See gorilla/sessions FilesystemStore.New().
func (s *DynamoDBStore) New(r *http.Request, name string) (*sessions.Session, error) {
	var err error
	session := sessions.NewSession(s, name)
	// make a copy
	options := *s.Options
	session.Options = &options
	session.IsNew = true
	if c, errCookie := r.Cookie(name); errCookie == nil {
		err = securecookie.DecodeMulti(name, c.Value, &session.ID, s.Codecs...)
		if err == nil {
			ok, err := s.load(session)
			session.IsNew = !(err == nil && ok) // not new if no error and data available
		}
	}
	return session, err
}

// Save adds a single session to the response.
func (s *DynamoDBStore) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	// Marked for deletion.
	if session.Options.MaxAge < 0 {
		if err := s.delete(session.ID); err != nil {
			return err
		}
		http.SetCookie(w, sessions.NewCookie(session.Name(), "", session.Options))
	} else {
		// Build an alphanumeric key for the session id.
		if session.ID == "" {
			session.ID = strings.TrimRight(base32.StdEncoding.EncodeToString(securecookie.GenerateRandomKey(32)), "=")
		}
		if err := s.save(session); err != nil {
			return err
		}
		encoded, err := securecookie.EncodeMulti(session.Name(), session.ID, s.Codecs...)
		if err != nil {
			return err
		}
		http.SetCookie(w, sessions.NewCookie(session.Name(), encoded, session.Options))
	}
	return nil
}

// save stores the session in DB.
func (s *DynamoDBStore) save(session *sessions.Session) error {
	b, err := s.serializer.Serialize(session)
	if err != nil {
		return err
	}
	age := session.Options.MaxAge
	// if session age == 0 (session cookie, still expire from DB after a period of DefaultMaxAge)
	if age == 0 {
		age = s.DefaultMaxAge
	}

	putInput := &dynamodb.PutItemInput{
		TableName: aws.String(s.Table),
		Item: map[string]*dynamodb.AttributeValue{ // Required
			"id": {
				S: aws.String(session.ID),
			},
			"data": {
				B: b,
			},
			"expires": {
				// add age seconds to now, convert to timestamp and convert to string.
				N: aws.String(strconv.Itoa(int(time.Now().Add(time.Duration(age) * time.Second).Unix()))),
			},
		},
	}

	_, err = s.Db.PutItem(putInput)

	return err
}

// load reads the session from DB.
// returns true if there is a session data in DB
func (s *DynamoDBStore) load(session *sessions.Session) (bool, error) {
	getInput := &dynamodb.GetItemInput{
		TableName: aws.String(s.Table),
		Key: map[string]*dynamodb.AttributeValue{
			"id": {
				S: aws.String(session.ID),
			},
		},
	}
	item, err := s.Db.GetItem(getInput)
	if err != nil {
		return false, err
	}

	if item.Item["id"] == nil {
		return false, nil
	}

	expiresString := *item.Item["expires"].N
	expiresInt, err := strconv.Atoi(expiresString)
	if err != nil {
		return false, err
	}
	expiresTime := time.Unix(int64(expiresInt), 0)
	if expiresTime.Before(time.Now()) {
		// session has expired - delete
		go s.delete(session.ID)
		return false, nil

	}

	return true, s.serializer.Deserialize(item.Item["data"].B, session)
}

// deletes a session frmo dynamoDb
func (s *DynamoDBStore) delete(sessionId string) error {
	deleteInput := &dynamodb.DeleteItemInput{
		TableName: aws.String(s.Table),
		Key: map[string]*dynamodb.AttributeValue{
			"id": {
				S: aws.String(sessionId),
			},
		},
	}
	_, err := s.Db.DeleteItem(deleteInput)
	return err
}

// scan session table and delete expires sessions
func (s *DynamoDBStore) doBackgroundExpiration() {

	s.Db.ScanPages(&dynamodb.ScanInput{TableName: aws.String(s.Table)},
		func(page *dynamodb.ScanOutput, lastPage bool) bool {
			for _, item := range page.Items {
				id := *item["id"].S
				expiresString := *item["expires"].N
				expiresInt, err := strconv.Atoi(expiresString)
				if err != nil {
					continue
				}
				expiresTime := time.Unix(int64(expiresInt), 0)
				if expiresTime.Before(time.Now()) {
					s.delete(id)
				}
			}
			return true
		})

}

// run an expiration run immediately on startup (in the background) and then repeat every expireScanInterval
func (s *DynamoDBStore) runBackgroundExpiration() {

	// run an initial deletion after a 10 second delay to let the app start up
	go func() {
		time.Sleep(10 * time.Second)
		s.doBackgroundExpiration()
	}()

	for {
		<-time.Tick(expireScanInterval)
		s.doBackgroundExpiration()
	}

}
