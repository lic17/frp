// Copyright 2018 fatedier, fatedier@gmail.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sub

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/fatedier/frp/pkg/config"
)

func init() {
	decryptCmd.PersistentFlags().StringVarP(&in, "in", "i", "", "input file")
	decryptCmd.PersistentFlags().StringVarP(&out, "out", "o", "", "output file")

	rootCmd.AddCommand(decryptCmd)
}

var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "decrypt the file",
	RunE: func(cmd *cobra.Command, args []string) error {
		if in == "" {
			fmt.Println("in must be set")
			os.Exit(1)
		}
		if out == "" {
			fmt.Println("out must be set")
			os.Exit(1)
		}
		b, err := os.ReadFile(in)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		content := string(b)

		content, err = config.Decrypt(content)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		err = os.WriteFile(out, []byte(content), 0o644)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		return nil
	},
}
