package mail

type MailSenderRepo interface {
	SendVerifyMessage()
}
