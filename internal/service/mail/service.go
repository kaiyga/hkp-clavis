package mail

type MailServiceInterface interface {
	SendMail(to []string, msg []byte)
}
