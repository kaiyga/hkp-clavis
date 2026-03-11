package pool

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"net/smtp"
	"sync"
	"sync/atomic"
	"time"
)

type Message struct {
	From      string
	To        []string
	Message   bytes.Buffer
	inProcess bool
}

type MessageTransaction struct {
	done bool
	key  string
	msg  *Message
	pool *MessagePool
}

func (s MessageTransaction) Done() {
	s.done = true
}

func (s MessageTransaction) Close() {
	if s.done {
		s.pool.Del(s.key)
		return
	}
	s.msg.inProcess = false
}

type MessagePool struct {
	m           *sync.Mutex
	messagePool map[string]*Message
}

func (p MessagePool) Put(m *Message) {
	if m == nil {
		return
	}
	p.m.Lock()

	h := sha256.New()
	h.Write(m.Message.Bytes())
	k := string(h.Sum(nil))

	p.messagePool[k] = m
	p.m.Unlock()
}

func (p MessagePool) Del(key string) {
	p.m.Lock()
	delete(p.messagePool, key)
	p.m.Unlock()
}

func (p MessagePool) Begin() chan MessageTransaction {
	c := make(chan MessageTransaction)
	go func() {
		for k, m := range p.messagePool {
			if !m.inProcess {
				p.m.Lock()
				m.inProcess = true
				c <- MessageTransaction{
					done: false,
					key:  k,
					msg:  m,
					pool: &p,
				}
				p.m.Unlock()
			}
			close(c)
		}
	}()
	return c
}

type PoolConfig struct {
	CountOfConnection            int32
	Identity, Username, Password string
	Host                         string
}

type SMTPPool struct {
	config            PoolConfig
	countOfConnection int32
	connections       chan *smtp.Client
	MessagePool       *MessagePool
}

// Get SMTPPoolConfig  return SMTPPool
func NewSMTPPool(conf PoolConfig) (*SMTPPool, error) {
	auth := smtp.PlainAuth(conf.Identity, conf.Username, conf.Password, conf.Host)

	pool := &SMTPPool{
		config:            conf,
		connections:       make(chan *smtp.Client, conf.CountOfConnection),
		countOfConnection: 0,
	}

	go pool.healthChecker(auth)

	// Init Connections
	for range conf.CountOfConnection {
		c, err := newClient(conf, auth)
		if err != nil {
			return nil, fmt.Errorf("pkg smtp pool: NewSMTPPool: Init Connections: %w", err)
		}
		// Add to pool
		pool.connections <- c
		pool.countOfConnection++
	}

	return pool, nil
}

func newClient(conf PoolConfig, auth smtp.Auth) (*smtp.Client, error) {
	c, err := smtp.Dial(conf.Host)
	if err != nil {
		return nil, fmt.Errorf("newClient: %w", err)
	}

	if err = c.Hello(conf.Identity); err != nil {
		return nil, err
	}
	// Check TLS
	if ok, _ := c.Extension("STARTTLS"); ok {
		config := &tls.Config{ServerName: conf.Host}
		if err = c.StartTLS(config); err != nil {
			return nil, fmt.Errorf("newClient: %w", err)
		}
	}
	// Auth
	if ok, _ := c.Extension("AUTH"); ok {
		if auth == nil {
			return nil, errors.New("newClient: auth is nil")
		}
		if err := c.Auth(auth); err != nil {
			return nil, fmt.Errorf("newClient: %w", err)
		}
	}

	if err := c.Noop(); err != nil {
		return nil, fmt.Errorf("newClient: c.Noop() error: %w", err)
	}
	return c, nil
}

// Daemon. Doing Helth-Check and Auto-Heal of SMTPPool
func (p *SMTPPool) healthChecker(auth smtp.Auth) {
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {

		// Auto-Heal Pool

		current := atomic.LoadInt32(&p.countOfConnection)
		needed := int32(p.config.CountOfConnection) - current
		if needed > 0 {
			for range p.config.CountOfConnection - p.countOfConnection {
				newConn, err := newClient(p.config, auth)
				if err != nil {
					fmt.Println("WARNING: pkg smtp pool: healthChecker: Create connection: %w", err)
					continue
				}
				p.connections <- newConn
				atomic.AddInt32(&p.countOfConnection, 1)
			}
		}

		select {
		case conn := <-p.connections:
			if err := conn.Noop(); err != nil {
				atomic.AddInt32(&p.countOfConnection, -1)
				conn.Close()
			} else {
				p.connections <- conn
			}
		default:
			// All Conns is busy
		}
	}
}

func (p *SMTPPool) SendMail(from string, to []string, mess []byte) error {
	return nil
}
