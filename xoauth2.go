package sasl

import (
	"fmt"
    "github.com/emersion/go-sasl"
)

// The XOAUTH2 mechanism name.
const XOAUTH2 = "XOAUTH2"

type XOAUTH2Options struct {
    Username string
    Token    string
}

type xoauth2Client struct {
    XOAUTH2Options
}

func (x *xoauth2Client) Start() (mech string, ir []byte, err error) {
    ir = []byte(fmt.Sprintf("user=%s\x01auth=Bearer %s\x01\x01", x.Username, x.Token))
    return XOAUTH2, ir, nil
}

func (x *xoauth2Client) Next(challenge []byte) (response []byte, err error) {
    return nil, sasl.ErrUnexpectedServerChallenge
}

func NewXOAUTH2Client(username, token string) sasl.Client {
    return &xoauth2Client{
        XOAUTH2Options: XOAUTH2Options{
            Username: username,
            Token:    token,
        },
    }
}

type XOAUTH2Authenticator func(opts XOAUTH2Options) error

type xoauth2Server struct {
    done         bool
    failErr      error
    authenticate XOAUTH2Authenticator
}

func (a *xoauth2Server) Next(response []byte) (challenge []byte, done bool, err error) {
    if a.done {
        return nil, true, a.failErr
    }

    if a.authenticate != nil {
        err := a.authenticate(XOAUTH2Options{
            Username: string(response),
            Token:    string(response),
        })
        if err != nil {
            a.failErr = err
            return nil, false, err
        }
    }

    a.done = true
    return nil, true, nil
}

func NewXOAUTH2Server(authenticator XOAUTH2Authenticator) sasl.Server {
    return &xoauth2Server{
        authenticate: authenticator,
    }
}
