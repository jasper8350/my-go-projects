package main

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "myapp",
		Short: "MyApp is a sample CLI application",
	}

	// Add commands
	rootCmd.AddCommand(cmdHello)

	// Enable bash completion
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.AddCommand(&cobra.Command{Use: "completion", Run: func(cmd *cobra.Command, args []string) { rootCmd.GenBashCompletion(os.Stdout) }})

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

var cmdHello = &cobra.Command{
	Use:   "hello [name]",
	Short: "Prints hello to the provided name",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		name := args[0]
		fmt.Printf("Hello, %s!\n", name)
	},
}
