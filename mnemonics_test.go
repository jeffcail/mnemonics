package mnemonics_test

import (
	"fmt"
	"github.com/jeffcail/mnemonics"
	"testing"
)

func TestGenerate12Mnemonic(t *testing.T) {
	fmt.Printf("mnemonic: %s\n", mnemonics.Generate12Mnemonic())
}

func TestGenerate24Mnemonic(t *testing.T) {
	fmt.Printf("mnemonic: %s\n", mnemonics.Generate24Mnemonic())
}
