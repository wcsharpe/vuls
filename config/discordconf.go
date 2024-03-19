package config

import (
	"github.com/asaskevich/govalidator"
	"golang.org/x/xerrors"
)

// DiscordConf holds configuration for sending messages to Discord
type DiscordConf struct {
	WebhookURL string `valid:"url" json:"-" toml:"webhookURL,omitempty"`
	// Add other configuration fields as needed
	Channel     string   `json:"-" toml:"channel,omitempty"`
	AuthUser    string   `json:"-" toml:"authUser,omitempty"`
	NotifyUsers []string `toml:"notifyUsers,omitempty" json:"-"`
	Text        string   `json:"-"`
	Enabled     bool     `toml:"-" json:"-"`
}

// Validate validates configuration
func (c *DiscordConf) Validate() (errs []error) {
	if !c.Enabled {
		return
	}

	if len(c.WebhookURL) == 0 {
		errs = append(errs, xerrors.New("discord.webhookURL must not be empty"))
	}

	if len(c.Channel) == 0 {
		errs = append(errs, xerrors.New("discord.channel must not be empty"))
	}

	if len(c.AuthUser) == 0 {
		errs = append(errs, xerrors.New("discord.authUser must not be empty"))
	}

	_, err := govalidator.ValidateStruct(c)
	if err != nil {
		errs = append(errs, err)
	}

	return
}
