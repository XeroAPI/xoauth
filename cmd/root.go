package cmd

import (
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/XeroAPI/xoauth/pkg/config"
	"github.com/XeroAPI/xoauth/pkg/connect"
	"github.com/XeroAPI/xoauth/pkg/tokens"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "xoauth",
	Short: "🔒 XOAuth – Get yourself some OAuth2 tokens",
	Long: `
🔒 XOAuth

A tool to help you work with OpenId Connect APIs.`,
	Run: func(cmd *cobra.Command, args []string) {
		err := cmd.Help()

		if err != nil {
			log.Fatal(err)
		}
	},
}

func getEnv(key, fallback string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		value = fallback
	}
	return value
}

func init() {
	var fallbackPort = 8080
	var defaultPort, portErr = strconv.Atoi(getEnv("XOAUTH_PORT", fmt.Sprintf("%d", 8080)))

	if portErr != nil {
		defaultPort = fallbackPort
	}

	var ShowSecrets bool
	var listCmd = &cobra.Command{
		Use:   "list",
		Short: "List all the OpenId Connect connections you've set up",
		Args: func(cmd *cobra.Command, args []string) error {
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			config.ListAll(ShowSecrets)
		},
	}

	listCmd.PersistentFlags().BoolVarP(&ShowSecrets, "secrets", "s", false, "Show client secrets")

	var DryRun bool
	var Port int

	var connectCmd = &cobra.Command{
		Use:   "connect [connection_name]",
		Short: "Use a saved connection to request credentials from an OpenId Connect provider",
		Args:  config.ValidateClientNameCmdArgs,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 1 {
				connect.Authorise(args[0], DryRun, Port)
				return
			}

			connection, err := config.ChooseClient()

			if err != nil {
				panic(err)
			}

			connect.Authorise(connection, DryRun, Port)
		},
	}

	connectCmd.PersistentFlags().BoolVarP(&DryRun, "dry-run", "d", false, "Output the authorisation request URL instead of perforiming the request")
	connectCmd.PersistentFlags().IntVarP(&Port, "port", "p", defaultPort, "Localhost port")

	var deleteCmd = &cobra.Command{
		Use:   "delete [connection]",
		Short: "Delete a connection from your local machine",
		Args:  config.ValidateClientNameCmdArgs,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 1 {
				config.ConfirmDelete(args[0])
				return
			}

			connection, err := config.ChooseClient()

			if err != nil {
				panic(err)
			}

			config.ConfirmDelete(connection)
		},
	}

	var setupCmd = &cobra.Command{
		Use:   "setup [clientName]",
		Short: "Set up a new connection to an OpenId Connect provider",
		Args:  config.ValidateClientNameCmdArgs,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) < 1 {
				config.InteractiveSetup("", defaultPort)
				return
			}
			config.InteractiveSetup(args[0], defaultPort)
		},
	}

	var addScopeCmd = &cobra.Command{
		Use:   "add-scope [clientName] [...scopes]",
		Short: "Add scopes to a connection",
		Args:  config.ValidateScopeCmdArgs,
		Run: func(cmd *cobra.Command, args []string) {
			config.AddScope(args[0], args[1:]...)
		},
	}

	var removeScopeCmd = &cobra.Command{
		Use:   "remove-scope [clientName] [...scopes]",
		Short: "Remove scopes from a connection",
		Args:  config.ValidateScopeCmdArgs,
		Run: func(cmd *cobra.Command, args []string) {
			config.RemoveScope(args[0], args[1:]...)
		},
	}

	var updateSecretCmd = &cobra.Command{
		Use:   "update-secret [clientName] [clientSecret]",
		Short: "Update the client secret for a connection",
		Args:  config.ValidateSecretCmdArgs,
		Run: func(cmd *cobra.Command, args []string) {
			config.UpdateSecret(args[0], args[1])
		},
	}

	var EnvFlag bool
	var ForceRefresh bool
	var tokenCmd = &cobra.Command{
		Use:   "token [clientName]",
		Short: "Get the last saved set of tokens out of the keychain",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 1 {
				tokens.ShowTokens(args[0], EnvFlag, ForceRefresh)
				return
			}

			client, err := config.ChooseClient()

			if err != nil {
				log.Fatalln(err)
			}

			tokens.ShowTokens(client, EnvFlag, ForceRefresh)
		},
	}

	tokenCmd.PersistentFlags().BoolVarP(&EnvFlag, "env", "e", false, "Export tokens to environment")
	tokenCmd.PersistentFlags().BoolVarP(&ForceRefresh, "refresh", "r", false, "Force a token refresh")

	var DoctorPort int
	var doctorCmd = &cobra.Command{
		Use:   "doctor",
		Short: "Checks that xoauth is configured properly",
		Run: func(cmd *cobra.Command, args []string) {
			config.Doctor(DoctorPort)
		},
	}
	doctorCmd.PersistentFlags().IntVarP(&DoctorPort, "port", "p", defaultPort, "Localhost port")

	setupCmd.AddCommand(addScopeCmd)
	setupCmd.AddCommand(removeScopeCmd)
	setupCmd.AddCommand(updateSecretCmd)

	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(connectCmd)
	rootCmd.AddCommand(setupCmd)
	rootCmd.AddCommand(deleteCmd)
	rootCmd.AddCommand(doctorCmd)
	rootCmd.AddCommand(tokenCmd)
}

func Execute() error {
	return rootCmd.Execute()
}
