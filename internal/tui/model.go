package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/filepicker"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/gocryptic/gocryptic/internal/crypto"
	"github.com/gocryptic/gocryptic/internal/hash"
	"github.com/gocryptic/gocryptic/internal/keygen"
)

// ---------------------------------------------------------------------------
// Screens
// ---------------------------------------------------------------------------

type screen int

const (
	screenMenu screen = iota
	screenEncrypt
	screenDecrypt
	screenHash
	screenKeygen
	screenEncode
	screenSign
	screenVerify
	screenFilePicker
	screenResult
	screenWorking
)

// ---------------------------------------------------------------------------
// Menu items
// ---------------------------------------------------------------------------

type menuItem struct {
	title, desc string
	target      screen
}

func (m menuItem) Title() string       { return m.title }
func (m menuItem) Description() string { return m.desc }
func (m menuItem) FilterValue() string { return m.title }

var menuItems = []list.Item{
	menuItem{"Encrypt", "Encrypt text, files, or directories", screenEncrypt},
	menuItem{"Decrypt", "Decrypt text or files", screenDecrypt},
	menuItem{"Hash", "Compute cryptographic hashes", screenHash},
	menuItem{"Keygen", "Generate keys and passwords", screenKeygen},
	menuItem{"Encode / Decode", "Base64 and hex encoding", screenEncode},
	menuItem{"Sign", "Sign data with a private key", screenSign},
	menuItem{"Verify", "Verify a digital signature", screenVerify},
}

// ---------------------------------------------------------------------------
// Result message
// ---------------------------------------------------------------------------

type resultMsg struct {
	title   string
	content string
	isError bool
}

type doneMsg struct{ result resultMsg }
type copiedMsg struct{}

// ---------------------------------------------------------------------------
// Form field index helpers
// ---------------------------------------------------------------------------

// encrypt form fields
const (
	fEncInput = iota
	fEncKey
	fEncOutput
	fEncCount
)

// decrypt form fields
const (
	fDecInput = iota
	fDecKey
	fDecOutput
	fDecCount
)

// hash form fields
const (
	fHashInput = iota
	fHashCount
)

// keygen form fields
const (
	fKeygenOutput = iota
	fKeygenExtra
	fKeygenCount
)

// encode form fields
const (
	fEncodeInput = iota
	fEncodeCount
)

// sign form fields
const (
	fSignFile = iota
	fSignKey
	fSignOutput
	fSignCount
)

// verify form fields
const (
	fVerifyFile = iota
	fVerifyKey
	fVerifySig
	fVerifyCount
)

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

type Model struct {
	// Navigation
	current  screen
	previous screen
	width    int
	height   int

	// Menu
	list list.Model

	// Text inputs — reused across screens
	inputs    []textinput.Model
	focusIdx  int

	// Option selectors (algorithm, type, etc.)
	optionIdx int
	options   []string

	// Toggle (encode/decode, etc.)
	toggleIdx int
	toggles   []string

	// File picker
	fp             filepicker.Model
	fpCallback     screen  // screen to return to after pick
	fpField        int     // which field to populate
	fpSelectedPath string

	// Spinner (working screen)
	spinner spinner.Model
	working bool

	// Result
	result  resultMsg
	copied  bool // true briefly after clipboard copy

	// Error
	err string
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

func NewModel() Model {
	// Build menu list.
	delegate := list.NewDefaultDelegate()
	delegate.ShowDescription = true
	delegate.Styles.SelectedTitle = delegate.Styles.SelectedTitle.
		Foreground(colPurple).
		BorderLeftForeground(colPurple)
	delegate.Styles.SelectedDesc = delegate.Styles.SelectedDesc.
		Foreground(colFgMid).
		BorderLeftForeground(colPurple)

	l := list.New(menuItems, delegate, 40, 20)
	l.Title = "GoCryptic"
	l.Styles.Title = styleTitle.Background(colPurple).Foreground(lipgloss.Color("#ffffff")).Padding(0, 1)
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)
	l.SetShowHelp(false)

	// Spinner
	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = lipgloss.NewStyle().Foreground(colPurple)

	// File picker
	fp := filepicker.New()
	fp.CurrentDirectory, _ = os.Getwd()
	fp.ShowHidden = false

	return Model{
		current: screenMenu,
		list:    l,
		spinner: sp,
		fp:      fp,
	}
}

func (m Model) Init() tea.Cmd {
	return m.spinner.Tick
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.list.SetWidth(msg.Width - 8)
		m.list.SetHeight(msg.Height - 8)
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			if m.current == screenMenu {
				return m, tea.Quit
			}
		case "esc":
			if m.current == screenFilePicker {
				m.current = m.fpCallback
				return m, nil
			}
			if m.current == screenResult || m.current == screenWorking {
				m.current = m.previous
				return m, nil
			}
			m.current = screenMenu
			m.err = ""
			return m, nil
		}

	case doneMsg:
		m.working = false
		m.result = msg.result
		m.copied = false
		m.previous = m.current
		m.current = screenResult
		return m, nil

	case copiedMsg:
		m.copied = false
		return m, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}

	switch m.current {
	case screenMenu:
		return m.updateMenu(msg)
	case screenEncrypt:
		return m.updateEncrypt(msg)
	case screenDecrypt:
		return m.updateDecrypt(msg)
	case screenHash:
		return m.updateHash(msg)
	case screenKeygen:
		return m.updateKeygen(msg)
	case screenEncode:
		return m.updateEncode(msg)
	case screenSign:
		return m.updateSign(msg)
	case screenVerify:
		return m.updateVerify(msg)
	case screenFilePicker:
		return m.updateFilePicker(msg)
	case screenResult:
		return m.updateResult(msg)
	}

	return m, nil
}

// ---------------------------------------------------------------------------
// Menu
// ---------------------------------------------------------------------------

func (m Model) updateMenu(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "enter" {
			if item, ok := m.list.SelectedItem().(menuItem); ok {
				m.previous = screenMenu
				m.current = item.target
				m.err = ""
				m.initScreen(item.target)
				return m, nil
			}
		}
	}
	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

// initScreen sets up inputs when entering a screen.
func (m *Model) initScreen(s screen) {
	switch s {
	case screenEncrypt:
		m.inputs = makeInputs(fEncCount)
		m.inputs[fEncInput].Placeholder = "Text to encrypt (or leave blank to pick a file)"
		m.inputs[fEncKey].Placeholder = "Password"
		m.inputs[fEncKey].EchoMode = textinput.EchoPassword
		m.inputs[fEncKey].EchoCharacter = '•'
		m.inputs[fEncOutput].Placeholder = "Output path (optional)"
		m.inputs[fEncInput].Focus()
		m.focusIdx = fEncInput
		m.options = []string{"aes-gcm", "aes-cbc", "chacha20", "rsa", "ecdh"}
		m.optionIdx = 0

	case screenDecrypt:
		m.inputs = makeInputs(fDecCount)
		m.inputs[fDecInput].Placeholder = "Text (base64) or leave blank to pick a file"
		m.inputs[fDecKey].Placeholder = "Password"
		m.inputs[fDecKey].EchoMode = textinput.EchoPassword
		m.inputs[fDecKey].EchoCharacter = '•'
		m.inputs[fDecOutput].Placeholder = "Output path (optional)"
		m.inputs[fDecInput].Focus()
		m.focusIdx = fDecInput

	case screenHash:
		m.inputs = makeInputs(fHashCount)
		m.inputs[fHashInput].Placeholder = "Text to hash (or leave blank to pick a file)"
		m.inputs[fHashInput].Focus()
		m.focusIdx = fHashInput
		m.options = append([]string{"all"}, hash.Algorithms()...)
		m.optionIdx = 2 // default sha256

	case screenKeygen:
		m.inputs = makeInputs(fKeygenCount)
		m.inputs[fKeygenOutput].Placeholder = "Output path / prefix (e.g. mykey)"
		m.inputs[fKeygenExtra].Placeholder = "Length (passwords) or bits (RSA)"
		m.focusIdx = 0 // start on type selector
		m.options = []string{"aes", "chacha20", "rsa", "ecdsa", "ecdh", "password"}
		m.optionIdx = 0

	case screenEncode:
		m.inputs = makeInputs(fEncodeCount)
		m.inputs[fEncodeInput].Placeholder = "Text to encode/decode (or leave blank to pick a file)"
		m.inputs[fEncodeInput].Focus()
		m.focusIdx = fEncodeInput
		m.options = []string{"base64", "base64url", "base64raw", "hex"}
		m.optionIdx = 0
		m.toggles = []string{"encode", "decode"}
		m.toggleIdx = 0

	case screenSign:
		m.inputs = makeInputs(fSignCount)
		m.inputs[fSignFile].Placeholder = "File to sign (or pick below)"
		m.inputs[fSignKey].Placeholder = "Private key PEM path (or pick below)"
		m.inputs[fSignOutput].Placeholder = "Output signature path (optional)"
		m.inputs[fSignFile].Focus()
		m.focusIdx = fSignFile

	case screenVerify:
		m.inputs = makeInputs(fVerifyCount)
		m.inputs[fVerifyFile].Placeholder = "File to verify (or pick below)"
		m.inputs[fVerifyKey].Placeholder = "Public key PEM path (or pick below)"
		m.inputs[fVerifySig].Placeholder = "Signature file path (or pick below)"
		m.inputs[fVerifyFile].Focus()
		m.focusIdx = fVerifyFile
	}
}

func makeInputs(n int) []textinput.Model {
	inputs := make([]textinput.Model, n)
	for i := range inputs {
		t := textinput.New()
		t.CharLimit = 512
		inputs[i] = t
	}
	return inputs
}

// ---------------------------------------------------------------------------
// Encrypt
// ---------------------------------------------------------------------------

func (m Model) updateEncrypt(msg tea.Msg) (tea.Model, tea.Cmd) {
	// Focus slots: 0=input 1=key 2=output 3=algo 4=browse 5=encrypt
	total := fEncCount + 3
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "tab", "down":
			m.focusIdx = (m.focusIdx + 1) % total
			m.refocusInputs(fEncCount)
		case "shift+tab", "up":
			m.focusIdx = (m.focusIdx - 1 + total) % total
			m.refocusInputs(fEncCount)
		case "left":
			if m.focusIdx == fEncCount { // algo selector
				if m.optionIdx > 0 {
					m.optionIdx--
				}
			} else if m.focusIdx == fEncCount+2 { // encrypt button → browse
				m.focusIdx = fEncCount + 1
			}
		case "right":
			if m.focusIdx == fEncCount { // algo selector
				if m.optionIdx < len(m.options)-1 {
					m.optionIdx++
				}
			} else if m.focusIdx == fEncCount+1 { // browse → encrypt
				m.focusIdx = fEncCount + 2
			}
		case "f", "enter":
			if m.focusIdx == fEncCount+1 {
				m.fpCallback = screenEncrypt
				m.fpField = fEncInput
				m.current = screenFilePicker
				var cmd tea.Cmd
				m.fp, cmd = m.fp.Update(nil)
				return m, cmd
			}
			if msg.String() == "enter" && m.focusIdx == fEncCount+2 {
				return m, m.runEncrypt()
			}
		}
	}
	return m.updateInputs(msg, fEncCount)
}

func (m Model) runEncrypt() tea.Cmd {
	algo := m.options[m.optionIdx]
	inputText := m.inputs[fEncInput].Value()
	key := m.inputs[fEncKey].Value()
	outPath := m.inputs[fEncOutput].Value()

	m.working = true
	m.previous = screenEncrypt
	m.current = screenWorking

	return func() tea.Msg {
		var ct []byte
		var err error

		if inputText != "" {
			switch algo {
			case "aes-gcm":
				ct, err = crypto.EncryptAESGCM([]byte(inputText), key)
			case "aes-cbc":
				ct, err = crypto.EncryptAESCBC([]byte(inputText), key)
			case "chacha20":
				ct, err = crypto.EncryptChaCha20([]byte(inputText), key)
			default:
				return doneMsg{resultMsg{title: "Error", content: "Use --file for RSA/ECDH encryption", isError: true}}
			}
			if err != nil {
				return doneMsg{resultMsg{title: "Encryption failed", content: err.Error(), isError: true}}
			}
			encoded := encodeBase64(ct)
			if outPath != "" {
				_ = os.WriteFile(outPath, []byte(encoded), 0644)
				return doneMsg{resultMsg{title: "Encrypted", content: fmt.Sprintf("Written to %s", outPath)}}
			}
			return doneMsg{resultMsg{title: "Encrypted (base64)", content: encoded}}
		}

		// File mode
		if m.fpSelectedPath != "" {
			data, readErr := os.ReadFile(m.fpSelectedPath)
			if readErr != nil {
				return doneMsg{resultMsg{title: "Error", content: readErr.Error(), isError: true}}
			}
			switch algo {
			case "aes-gcm":
				ct, err = crypto.EncryptAESGCM(data, key)
			case "aes-cbc":
				ct, err = crypto.EncryptAESCBC(data, key)
			case "chacha20":
				ct, err = crypto.EncryptChaCha20(data, key)
			default:
				return doneMsg{resultMsg{title: "Error", content: "RSA/ECDH not supported in TUI file mode yet", isError: true}}
			}
			if err != nil {
				return doneMsg{resultMsg{title: "Encryption failed", content: err.Error(), isError: true}}
			}
			dest := outPath
			if dest == "" {
				dest = m.fpSelectedPath + ".gcry"
			}
			if writeErr := os.WriteFile(dest, ct, 0644); writeErr != nil {
				return doneMsg{resultMsg{title: "Error writing output", content: writeErr.Error(), isError: true}}
			}
			return doneMsg{resultMsg{title: "Encrypted", content: fmt.Sprintf("%s → %s", filepath.Base(m.fpSelectedPath), filepath.Base(dest))}}
		}

		return doneMsg{resultMsg{title: "Error", content: "No input provided — enter text or pick a file", isError: true}}
	}
}

// ---------------------------------------------------------------------------
// Decrypt
// ---------------------------------------------------------------------------

func (m Model) updateDecrypt(msg tea.Msg) (tea.Model, tea.Cmd) {
	// Focus slots: 0=input 1=key 2=output 3=browse 4=decrypt
	total := fDecCount + 3
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "tab", "down":
			m.focusIdx = (m.focusIdx + 1) % total
			m.refocusInputs(fDecCount)
		case "shift+tab", "up":
			m.focusIdx = (m.focusIdx - 1 + total) % total
			m.refocusInputs(fDecCount)
		case "left":
			if m.focusIdx == fDecCount+2 {
				m.focusIdx = fDecCount + 1
			}
		case "right":
			if m.focusIdx == fDecCount+1 {
				m.focusIdx = fDecCount + 2
			}
		case "f", "enter":
			if m.focusIdx == fDecCount+1 {
				m.fpCallback = screenDecrypt
				m.fpField = fDecInput
				m.current = screenFilePicker
				var cmd tea.Cmd
				m.fp, cmd = m.fp.Update(nil)
				return m, cmd
			}
			if msg.String() == "enter" && m.focusIdx == fDecCount+2 {
				return m, m.runDecrypt()
			}
		}
	}
	return m.updateInputs(msg, fDecCount)
}

func (m Model) runDecrypt() tea.Cmd {
	inputText := strings.TrimSpace(m.inputs[fDecInput].Value())
	inputText = strings.ReplaceAll(inputText, "\n", "")
	inputText = strings.ReplaceAll(inputText, " ", "")
	key := m.inputs[fDecKey].Value()
	outPath := m.inputs[fDecOutput].Value()

	m.previous = screenDecrypt
	m.current = screenWorking

	return func() tea.Msg {
		if inputText != "" {
			raw, err := decodeBase64(inputText)
			if err != nil {
				return doneMsg{resultMsg{title: "Error", content: "Input is not valid base64: " + err.Error(), isError: true}}
			}
			pt, err := crypto.DecryptAuto(raw, key)
			if err != nil {
				return doneMsg{resultMsg{title: "Decryption failed", content: err.Error(), isError: true}}
			}
			if outPath != "" {
				_ = os.WriteFile(outPath, pt, 0644)
				return doneMsg{resultMsg{title: "Decrypted", content: fmt.Sprintf("Written to %s", outPath)}}
			}
			return doneMsg{resultMsg{title: "Decrypted", content: string(pt)}}
		}

		if m.fpSelectedPath != "" {
			data, err := os.ReadFile(m.fpSelectedPath)
			if err != nil {
				return doneMsg{resultMsg{title: "Error", content: err.Error(), isError: true}}
			}
			pt, err := crypto.DecryptAuto(data, key)
			if err != nil {
				return doneMsg{resultMsg{title: "Decryption failed", content: err.Error(), isError: true}}
			}
			dest := outPath
			if dest == "" {
				dest = strings.TrimSuffix(m.fpSelectedPath, ".gcry")
				if dest == m.fpSelectedPath {
					dest = m.fpSelectedPath + ".dec"
				}
			}
			if err := os.WriteFile(dest, pt, 0644); err != nil {
				return doneMsg{resultMsg{title: "Error writing output", content: err.Error(), isError: true}}
			}
			return doneMsg{resultMsg{title: "Decrypted", content: fmt.Sprintf("%s → %s", filepath.Base(m.fpSelectedPath), filepath.Base(dest))}}
		}

		return doneMsg{resultMsg{title: "Error", content: "No input provided", isError: true}}
	}
}

// ---------------------------------------------------------------------------
// Hash
// ---------------------------------------------------------------------------

func (m Model) updateHash(msg tea.Msg) (tea.Model, tea.Cmd) {
	// Focus slots: 0=input 1=algo 2=browse 3=hash
	total := fHashCount + 3
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "tab", "down":
			m.focusIdx = (m.focusIdx + 1) % total
			m.refocusInputs(fHashCount)
		case "shift+tab", "up":
			m.focusIdx = (m.focusIdx - 1 + total) % total
			m.refocusInputs(fHashCount)
		case "left":
			if m.focusIdx == fHashCount {
				if m.optionIdx > 0 {
					m.optionIdx--
				}
			} else if m.focusIdx == fHashCount+2 {
				m.focusIdx = fHashCount + 1
			}
		case "right":
			if m.focusIdx == fHashCount {
				if m.optionIdx < len(m.options)-1 {
					m.optionIdx++
				}
			} else if m.focusIdx == fHashCount+1 {
				m.focusIdx = fHashCount + 2
			}
		case "f", "enter":
			if m.focusIdx == fHashCount+1 {
				m.fpCallback = screenHash
				m.fpField = fHashInput
				m.current = screenFilePicker
				var cmd tea.Cmd
				m.fp, cmd = m.fp.Update(nil)
				return m, cmd
			}
			if msg.String() == "enter" && m.focusIdx == fHashCount+2 {
				return m, m.runHash()
			}
		}
	}
	return m.updateInputs(msg, fHashCount)
}

func (m Model) runHash() tea.Cmd {
	inputText := m.inputs[fHashInput].Value()
	algo := m.options[m.optionIdx]
	filePath := m.fpSelectedPath

	m.previous = screenHash
	m.current = screenWorking

	return func() tea.Msg {
		var results map[string]string
		var single string
		var err error

		if inputText != "" {
			data := []byte(inputText)
			if algo == "all" {
				results = hash.SumAll(data)
			} else {
				single, err = hash.Sum(data, algo)
				if err != nil {
					return doneMsg{resultMsg{title: "Error", content: err.Error(), isError: true}}
				}
			}
		} else if filePath != "" {
			if algo == "all" {
				results, err = hash.SumFileAll(filePath)
				if err != nil {
					return doneMsg{resultMsg{title: "Error", content: err.Error(), isError: true}}
				}
			} else {
				single, err = hash.SumFile(filePath, algo)
				if err != nil {
					return doneMsg{resultMsg{title: "Error", content: err.Error(), isError: true}}
				}
			}
		} else {
			return doneMsg{resultMsg{title: "Error", content: "No input provided", isError: true}}
		}

		if results != nil {
			var sb strings.Builder
			for _, a := range hash.Algorithms() {
				if d, ok := results[a]; ok {
					sb.WriteString(fmt.Sprintf("%-10s %s\n", strings.ToUpper(a), d))
				}
			}
			return doneMsg{resultMsg{title: "Hashes", content: strings.TrimRight(sb.String(), "\n")}}
		}
		return doneMsg{resultMsg{title: strings.ToUpper(algo), content: single}}
	}
}

// ---------------------------------------------------------------------------
// Keygen
// ---------------------------------------------------------------------------

func (m Model) updateKeygen(msg tea.Msg) (tea.Model, tea.Cmd) {
	// Focus slots: fKeygenCount=type-selector, fKeygenOutput=output, fKeygenExtra=bits, fKeygenCount+1=generate
	// We remap: 0=type 1=output 2=bits 3=generate
	total := 4
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "tab", "down":
			m.focusIdx = (m.focusIdx + 1) % total
			m.refocusKeygen()
		case "shift+tab", "up":
			m.focusIdx = (m.focusIdx - 1 + total) % total
			m.refocusKeygen()
		case "left":
			if m.focusIdx == 0 {
				if m.optionIdx > 0 {
					m.optionIdx--
				}
			}
		case "right":
			if m.focusIdx == 0 {
				if m.optionIdx < len(m.options)-1 {
					m.optionIdx++
				}
			}
		case "enter":
			if m.focusIdx == 3 {
				return m, m.runKeygen()
			}
		}
	}
	// Route input updates to the correct field
	if m.focusIdx == 1 {
		var cmd tea.Cmd
		m.inputs[fKeygenOutput], cmd = m.inputs[fKeygenOutput].Update(msg)
		return m, cmd
	}
	if m.focusIdx == 2 {
		var cmd tea.Cmd
		m.inputs[fKeygenExtra], cmd = m.inputs[fKeygenExtra].Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m *Model) refocusKeygen() {
	m.inputs[fKeygenOutput].Blur()
	m.inputs[fKeygenExtra].Blur()
	if m.focusIdx == 1 {
		m.inputs[fKeygenOutput].Focus()
	} else if m.focusIdx == 2 {
		m.inputs[fKeygenExtra].Focus()
	}
}

func (m Model) runKeygen() tea.Cmd {
	keyType := m.options[m.optionIdx]
	outPrefix := m.inputs[fKeygenOutput].Value()
	extra := m.inputs[fKeygenExtra].Value()

	m.previous = screenKeygen
	m.current = screenWorking

	return func() tea.Msg {
		switch keyType {
		case "aes":
			bits := 256
			fmt.Sscanf(extra, "%d", &bits)
			key, err := keygen.GenerateAESKey(bits)
			if err != nil {
				return doneMsg{resultMsg{title: "Error", content: err.Error(), isError: true}}
			}
			return doneMsg{resultMsg{title: fmt.Sprintf("AES-%d Key (hex)", bits), content: encodeHex(key)}}

		case "chacha20":
			key, err := keygen.GenerateChaChaKey()
			if err != nil {
				return doneMsg{resultMsg{title: "Error", content: err.Error(), isError: true}}
			}
			return doneMsg{resultMsg{title: "XChaCha20 Key (hex)", content: encodeHex(key)}}

		case "rsa":
			bits := 4096
			fmt.Sscanf(extra, "%d", &bits)
			priv := outPrefix + "_priv.pem"
			pub := outPrefix + "_pub.pem"
			if outPrefix == "" {
				priv, pub = "priv.pem", "pub.pem"
			}
			if err := keygen.GenerateRSAKeyPair(bits, priv, pub); err != nil {
				return doneMsg{resultMsg{title: "Error", content: err.Error(), isError: true}}
			}
			return doneMsg{resultMsg{title: fmt.Sprintf("RSA-%d Key Pair", bits), content: fmt.Sprintf("Private: %s\nPublic:  %s", priv, pub)}}

		case "ecdsa", "ecdh":
			priv := outPrefix + "_priv.pem"
			pub := outPrefix + "_pub.pem"
			if outPrefix == "" {
				priv, pub = "priv.pem", "pub.pem"
			}
			if err := keygen.GenerateECDSAKeyPair(priv, pub); err != nil {
				return doneMsg{resultMsg{title: "Error", content: err.Error(), isError: true}}
			}
			return doneMsg{resultMsg{title: "ECDSA/ECDH P-256 Key Pair", content: fmt.Sprintf("Private: %s\nPublic:  %s", priv, pub)}}

		case "password":
			length := 24
			fmt.Sscanf(extra, "%d", &length)
			pw, err := keygen.GeneratePassword(length, true)
			if err != nil {
				return doneMsg{resultMsg{title: "Error", content: err.Error(), isError: true}}
			}
			return doneMsg{resultMsg{title: fmt.Sprintf("Password (%d chars)", length), content: pw}}
		}
		return doneMsg{resultMsg{title: "Error", content: "Unknown key type", isError: true}}
	}
}

// ---------------------------------------------------------------------------
// Encode
// ---------------------------------------------------------------------------

func (m Model) updateEncode(msg tea.Msg) (tea.Model, tea.Cmd) {
	// Focus slots: 0=input 1=format 2=mode 3=browse 4=run
	const (
		eInput  = 0
		eFormat = 1
		eMode   = 2
		eBrowse = 3
		eRun    = 4
		eTotal  = 5
	)
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "tab", "down":
			m.focusIdx = (m.focusIdx + 1) % eTotal
			if m.focusIdx == eInput {
				m.inputs[fEncodeInput].Focus()
			} else {
				m.inputs[fEncodeInput].Blur()
			}
		case "shift+tab", "up":
			m.focusIdx = (m.focusIdx - 1 + eTotal) % eTotal
			if m.focusIdx == eInput {
				m.inputs[fEncodeInput].Focus()
			} else {
				m.inputs[fEncodeInput].Blur()
			}
		case "left":
			if m.focusIdx == eFormat {
				if m.optionIdx > 0 {
					m.optionIdx--
				}
			} else if m.focusIdx == eMode {
				m.toggleIdx = 0
			} else if m.focusIdx == eRun {
				m.focusIdx = eBrowse
			}
		case "right":
			if m.focusIdx == eFormat {
				if m.optionIdx < len(m.options)-1 {
					m.optionIdx++
				}
			} else if m.focusIdx == eMode {
				m.toggleIdx = 1
			} else if m.focusIdx == eBrowse {
				m.focusIdx = eRun
			}
		case "f", "enter":
			if m.focusIdx == eBrowse {
				m.fpCallback = screenEncode
				m.fpField = fEncodeInput
				m.current = screenFilePicker
				var cmd tea.Cmd
				m.fp, cmd = m.fp.Update(nil)
				return m, cmd
			}
			if msg.String() == "enter" && m.focusIdx == eRun {
				return m, m.runEncode()
			}
		}
	}
	if m.focusIdx == eInput {
		var cmd tea.Cmd
		m.inputs[fEncodeInput], cmd = m.inputs[fEncodeInput].Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m Model) viewEncode() string {
	acc := accentEncode
	var b strings.Builder
	b.WriteString(accentTitle("Encode / Decode", acc) + "\n\n")
	b.WriteString(renderFieldAccent("Input", m.inputs[fEncodeInput], m.focusIdx == 0, acc) + "\n")
	b.WriteString(renderSelectorAccent("Format", m.options, m.optionIdx, m.focusIdx == 1, acc) + "\n")
	b.WriteString(renderToggleAccent(m.toggles, m.toggleIdx, m.focusIdx == 2, acc) + "\n\n")
	b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top,
		renderButtonAccent("  Browse file (f)  ", m.focusIdx == 3, acc),
		"   ",
		renderButtonAccent("  Run  ", m.focusIdx == 4, acc),
	) + "\n")
	if m.fpSelectedPath != "" {
		b.WriteString("\n" + stylePath.Render("File: "+m.fpSelectedPath) + "\n")
	}
	b.WriteString(renderHelp())
	return styleApp.Render(b.String())
}

func (m Model) runEncode() tea.Cmd {
	inputText := m.inputs[fEncodeInput].Value()
	format := m.options[m.optionIdx]
	isDecode := m.toggleIdx == 1

	m.previous = screenEncode
	m.current = screenWorking

	return func() tea.Msg {
		var data []byte
		if inputText != "" {
			data = []byte(inputText)
		} else if m.fpSelectedPath != "" {
			var err error
			data, err = os.ReadFile(m.fpSelectedPath)
			if err != nil {
				return doneMsg{resultMsg{title: "Error", content: err.Error(), isError: true}}
			}
		} else {
			return doneMsg{resultMsg{title: "Error", content: "No input provided", isError: true}}
		}

		if isDecode {
			var result []byte
			var err error
			switch format {
			case "hex":
				result, err = decodeHex(string(data))
			default:
				result, err = decodeBase64(strings.TrimSpace(string(data)))
			}
			if err != nil {
				return doneMsg{resultMsg{title: "Error", content: err.Error(), isError: true}}
			}
			return doneMsg{resultMsg{title: "Decoded", content: string(result)}}
		}

		var result string
		switch format {
		case "base64":
			result = encodeBase64(data)
		case "base64url":
			result = encodeBase64URL(data)
		case "base64raw":
			result = encodeBase64Raw(data)
		case "hex":
			result = encodeHex(data)
		}
		return doneMsg{resultMsg{title: fmt.Sprintf("Encoded (%s)", format), content: result}}
	}
}

// ---------------------------------------------------------------------------
// Sign
// ---------------------------------------------------------------------------

func (m Model) updateSign(msg tea.Msg) (tea.Model, tea.Cmd) {
	// Focus slots: 0=file 1=key 2=output 3=browse-file 4=browse-key 5=sign
	const (
		sFile       = 0
		sKey        = 1
		sOutput     = 2
		sBrowseFile = 3
		sBrowseKey  = 4
		sSign       = 5
		sTotal      = 6
	)
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "tab", "down":
			m.focusIdx = (m.focusIdx + 1) % sTotal
			m.refocusSignInputs()
		case "shift+tab", "up":
			m.focusIdx = (m.focusIdx - 1 + sTotal) % sTotal
			m.refocusSignInputs()
		case "left":
			if m.focusIdx == sBrowseKey {
				m.focusIdx = sBrowseFile
			} else if m.focusIdx == sSign {
				m.focusIdx = sBrowseKey
			}
		case "right":
			if m.focusIdx == sBrowseFile {
				m.focusIdx = sBrowseKey
			} else if m.focusIdx == sBrowseKey {
				m.focusIdx = sSign
			}
		case "f", "enter":
			if m.focusIdx == sBrowseFile {
				m.fpCallback = screenSign
				m.fpField = fSignFile
				m.current = screenFilePicker
				var cmd tea.Cmd
				m.fp, cmd = m.fp.Update(nil)
				return m, cmd
			}
			if m.focusIdx == sBrowseKey {
				m.fpCallback = screenSign
				m.fpField = fSignKey
				m.current = screenFilePicker
				var cmd tea.Cmd
				m.fp, cmd = m.fp.Update(nil)
				return m, cmd
			}
			if msg.String() == "enter" && m.focusIdx == sSign {
				return m, m.runSign()
			}
		}
	}
	switch m.focusIdx {
	case sFile:
		var cmd tea.Cmd
		m.inputs[fSignFile], cmd = m.inputs[fSignFile].Update(msg)
		return m, cmd
	case sKey:
		var cmd tea.Cmd
		m.inputs[fSignKey], cmd = m.inputs[fSignKey].Update(msg)
		return m, cmd
	case sOutput:
		var cmd tea.Cmd
		m.inputs[fSignOutput], cmd = m.inputs[fSignOutput].Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m *Model) refocusSignInputs() {
	m.inputs[fSignFile].Blur()
	m.inputs[fSignKey].Blur()
	m.inputs[fSignOutput].Blur()
	switch m.focusIdx {
	case 0:
		m.inputs[fSignFile].Focus()
	case 1:
		m.inputs[fSignKey].Focus()
	case 2:
		m.inputs[fSignOutput].Focus()
	}
}

func (m Model) runSign() tea.Cmd {
	filePath := m.inputs[fSignFile].Value()
	keyPath := m.inputs[fSignKey].Value()
	outPath := m.inputs[fSignOutput].Value()

	m.previous = screenSign
	m.current = screenWorking

	return func() tea.Msg {
		if filePath == "" || keyPath == "" {
			return doneMsg{resultMsg{title: "Error", content: "File and key paths are required", isError: true}}
		}
		data, err := os.ReadFile(filePath)
		if err != nil {
			return doneMsg{resultMsg{title: "Error reading file", content: err.Error(), isError: true}}
		}
		sig, err := signData(data, keyPath)
		if err != nil {
			return doneMsg{resultMsg{title: "Signing failed", content: err.Error(), isError: true}}
		}
		dest := outPath
		if dest == "" {
			dest = filePath + ".sig"
		}
		if err := os.WriteFile(dest, sig, 0644); err != nil {
			return doneMsg{resultMsg{title: "Error writing signature", content: err.Error(), isError: true}}
		}
		return doneMsg{resultMsg{title: "Signed", content: fmt.Sprintf("Signature written to %s\n%d bytes", dest, len(sig))}}
	}
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

func (m Model) updateVerify(msg tea.Msg) (tea.Model, tea.Cmd) {
	// Focus slots: 0=file 1=key 2=sig 3=browse-file 4=browse-key 5=browse-sig 6=verify
	const (
		vFile       = 0
		vKey        = 1
		vSig        = 2
		vBrowseFile = 3
		vBrowseKey  = 4
		vBrowseSig  = 5
		vVerify     = 6
		vTotal      = 7
	)
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "tab", "down":
			m.focusIdx = (m.focusIdx + 1) % vTotal
			m.refocusVerifyInputs()
		case "shift+tab", "up":
			m.focusIdx = (m.focusIdx - 1 + vTotal) % vTotal
			m.refocusVerifyInputs()
		case "left":
			if m.focusIdx > vBrowseFile && m.focusIdx <= vVerify {
				m.focusIdx--
			}
		case "right":
			if m.focusIdx >= vBrowseFile && m.focusIdx < vVerify {
				m.focusIdx++
			}
		case "f", "enter":
			switch m.focusIdx {
			case vBrowseFile:
				m.fpCallback = screenVerify
				m.fpField = fVerifyFile
				m.current = screenFilePicker
				var cmd tea.Cmd
				m.fp, cmd = m.fp.Update(nil)
				return m, cmd
			case vBrowseKey:
				m.fpCallback = screenVerify
				m.fpField = fVerifyKey
				m.current = screenFilePicker
				var cmd tea.Cmd
				m.fp, cmd = m.fp.Update(nil)
				return m, cmd
			case vBrowseSig:
				m.fpCallback = screenVerify
				m.fpField = fVerifySig
				m.current = screenFilePicker
				var cmd tea.Cmd
				m.fp, cmd = m.fp.Update(nil)
				return m, cmd
			case vVerify:
				if msg.String() == "enter" {
					return m, m.runVerify()
				}
			}
		}
	}
	switch m.focusIdx {
	case vFile:
		var cmd tea.Cmd
		m.inputs[fVerifyFile], cmd = m.inputs[fVerifyFile].Update(msg)
		return m, cmd
	case vKey:
		var cmd tea.Cmd
		m.inputs[fVerifyKey], cmd = m.inputs[fVerifyKey].Update(msg)
		return m, cmd
	case vSig:
		var cmd tea.Cmd
		m.inputs[fVerifySig], cmd = m.inputs[fVerifySig].Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m *Model) refocusVerifyInputs() {
	m.inputs[fVerifyFile].Blur()
	m.inputs[fVerifyKey].Blur()
	m.inputs[fVerifySig].Blur()
	switch m.focusIdx {
	case 0:
		m.inputs[fVerifyFile].Focus()
	case 1:
		m.inputs[fVerifyKey].Focus()
	case 2:
		m.inputs[fVerifySig].Focus()
	}
}

func (m Model) runVerify() tea.Cmd {
	filePath := m.inputs[fVerifyFile].Value()
	keyPath := m.inputs[fVerifyKey].Value()
	sigPath := m.inputs[fVerifySig].Value()

	m.previous = screenVerify
	m.current = screenWorking

	return func() tea.Msg {
		if filePath == "" || keyPath == "" || sigPath == "" {
			return doneMsg{resultMsg{title: "Error", content: "File, key, and signature paths are all required", isError: true}}
		}
		data, err := os.ReadFile(filePath)
		if err != nil {
			return doneMsg{resultMsg{title: "Error reading file", content: err.Error(), isError: true}}
		}
		sig, err := os.ReadFile(sigPath)
		if err != nil {
			return doneMsg{resultMsg{title: "Error reading signature", content: err.Error(), isError: true}}
		}
		if err := verifyData(data, sig, keyPath); err != nil {
			return doneMsg{resultMsg{title: "✗ Invalid", content: "Signature verification failed: " + err.Error(), isError: true}}
		}
		return doneMsg{resultMsg{title: "✓ Valid", content: "Signature is valid"}}
	}
}

// ---------------------------------------------------------------------------
// File picker
// ---------------------------------------------------------------------------

func (m Model) updateFilePicker(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	m.fp, cmd = m.fp.Update(msg)
	if didSelect, path := m.fp.DidSelectFile(msg); didSelect {
		if m.fpField < len(m.inputs) {
			m.inputs[m.fpField].SetValue(path)
		}
		m.fpSelectedPath = path
		m.current = m.fpCallback
	}
	return m, cmd
}

// ---------------------------------------------------------------------------
// Result
// ---------------------------------------------------------------------------

func (m Model) updateResult(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "c":
			if copyToClipboard(m.result.content) {
				m.copied = true
				return m, tea.Tick(2*time.Second, func(_ time.Time) tea.Msg {
					return copiedMsg{}
				})
			}
		case "enter", "esc":
			m.current = m.previous
			m.copied = false
			m.fpSelectedPath = ""
			return m, nil
		case "q":
			m.current = screenMenu
			m.copied = false
			m.fpSelectedPath = ""
			return m, nil
		}
	}
	return m, nil
}

// ---------------------------------------------------------------------------
// Shared input update
// ---------------------------------------------------------------------------

func (m Model) updateInputs(msg tea.Msg, count int) (tea.Model, tea.Cmd) {
	if m.focusIdx < count {
		var cmd tea.Cmd
		m.inputs[m.focusIdx], cmd = m.inputs[m.focusIdx].Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m *Model) refocusInputs(count int) {
	for i := range m.inputs {
		if i < count {
			m.inputs[i].Blur()
		}
	}
	if m.focusIdx < count {
		m.inputs[m.focusIdx].Focus()
	}
}

// ---------------------------------------------------------------------------
// View
// ---------------------------------------------------------------------------

func (m Model) View() string {
	switch m.current {
	case screenMenu:
		return m.viewMenu()
	case screenEncrypt:
		return m.viewEncrypt()
	case screenDecrypt:
		return m.viewDecrypt()
	case screenHash:
		return m.viewHash()
	case screenKeygen:
		return m.viewKeygen()
	case screenEncode:
		return m.viewEncode()
	case screenSign:
		return m.viewSign()
	case screenVerify:
		return m.viewVerify()
	case screenFilePicker:
		return m.viewFilePicker()
	case screenResult:
		return m.viewResult()
	case screenWorking:
		return m.viewWorking()
	}
	return ""
}

func (m Model) viewMenu() string {
	return styleApp.Render(m.list.View() + "\n" + styleHelp.Render("↑/↓ navigate  enter select  q quit"))
}

func (m Model) viewEncrypt() string {
	acc := accentEncrypt
	var b strings.Builder
	b.WriteString(accentTitle("Encrypt", acc) + "\n\n")
	b.WriteString(renderFieldAccent("Input text", m.inputs[fEncInput], m.focusIdx == fEncInput, acc) + "\n")
	b.WriteString(renderFieldAccent("Password", m.inputs[fEncKey], m.focusIdx == fEncKey, acc) + "\n")
	b.WriteString(renderFieldAccent("Output path", m.inputs[fEncOutput], m.focusIdx == fEncOutput, acc) + "\n")
	b.WriteString(renderSelectorAccent("Algorithm", m.options, m.optionIdx, m.focusIdx == fEncCount, acc) + "\n\n")
	b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top,
		renderButtonAccent("  Browse file (f)  ", m.focusIdx == fEncCount+1, acc),
		"   ",
		renderButtonAccent("  Encrypt  ", m.focusIdx == fEncCount+2, acc),
	) + "\n")
	if m.fpSelectedPath != "" {
		b.WriteString("\n" + stylePath.Render("File: "+m.fpSelectedPath) + "\n")
	}
	b.WriteString(renderHelp())
	return styleApp.Render(b.String())
}

func (m Model) viewDecrypt() string {
	acc := accentDecrypt
	var b strings.Builder
	b.WriteString(accentTitle("Decrypt", acc) + "\n\n")
	b.WriteString(renderFieldAccent("Input (base64)", m.inputs[fDecInput], m.focusIdx == fDecInput, acc) + "\n")
	b.WriteString(renderFieldAccent("Password", m.inputs[fDecKey], m.focusIdx == fDecKey, acc) + "\n")
	b.WriteString(renderFieldAccent("Output path", m.inputs[fDecOutput], m.focusIdx == fDecOutput, acc) + "\n\n")
	b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top,
		renderButtonAccent("  Browse file (f)  ", m.focusIdx == fDecCount+1, acc),
		"   ",
		renderButtonAccent("  Decrypt  ", m.focusIdx == fDecCount+2, acc),
	) + "\n")
	if m.fpSelectedPath != "" {
		b.WriteString("\n" + stylePath.Render("File: "+m.fpSelectedPath) + "\n")
	}
	b.WriteString(renderHelp())
	return styleApp.Render(b.String())
}

func (m Model) viewHash() string {
	acc := accentHash
	var b strings.Builder
	b.WriteString(accentTitle("Hash", acc) + "\n\n")
	b.WriteString(renderFieldAccent("Input text", m.inputs[fHashInput], m.focusIdx == fHashInput, acc) + "\n")
	b.WriteString(renderSelectorAccent("Algorithm", m.options, m.optionIdx, m.focusIdx == fHashCount, acc) + "\n\n")
	b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top,
		renderButtonAccent("  Browse file (f)  ", m.focusIdx == fHashCount+1, acc),
		"   ",
		renderButtonAccent("  Hash  ", m.focusIdx == fHashCount+2, acc),
	) + "\n")
	if m.fpSelectedPath != "" {
		b.WriteString("\n" + stylePath.Render("File: "+m.fpSelectedPath) + "\n")
	}
	b.WriteString(renderHelp())
	return styleApp.Render(b.String())
}

func (m Model) viewKeygen() string {
	acc := accentKeygen
	var b strings.Builder
	b.WriteString(accentTitle("Key Generation", acc) + "\n\n")
	b.WriteString(renderSelectorAccent("Type", m.options, m.optionIdx, m.focusIdx == 0, acc) + "\n")
	b.WriteString(renderFieldAccent("Output prefix", m.inputs[fKeygenOutput], m.focusIdx == 1, acc) + "\n")
	b.WriteString(renderFieldAccent("Bits / length", m.inputs[fKeygenExtra], m.focusIdx == 2, acc) + "\n\n")
	b.WriteString(renderButtonAccent("  Generate  ", m.focusIdx == 3, acc) + "\n")
	b.WriteString(renderHelp())
	return styleApp.Render(b.String())
}


func (m Model) viewSign() string {
	acc := accentSign
	var b strings.Builder
	b.WriteString(accentTitle("Sign", acc) + "\n\n")
	b.WriteString(renderFieldAccent("File to sign", m.inputs[fSignFile], m.focusIdx == 0, acc) + "\n")
	b.WriteString(renderFieldAccent("Private key", m.inputs[fSignKey], m.focusIdx == 1, acc) + "\n")
	b.WriteString(renderFieldAccent("Output .sig", m.inputs[fSignOutput], m.focusIdx == 2, acc) + "\n\n")
	b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top,
		renderButtonAccent("  Browse file (f)  ", m.focusIdx == 3, acc),
		"   ",
		renderButtonAccent("  Browse key (f)  ", m.focusIdx == 4, acc),
		"   ",
		renderButtonAccent("  Sign  ", m.focusIdx == 5, acc),
	) + "\n")
	b.WriteString(renderHelp())
	return styleApp.Render(b.String())
}

func (m Model) viewVerify() string {
	acc := accentVerify
	var b strings.Builder
	b.WriteString(accentTitle("Verify", acc) + "\n\n")
	b.WriteString(renderFieldAccent("File", m.inputs[fVerifyFile], m.focusIdx == 0, acc) + "\n")
	b.WriteString(renderFieldAccent("Public key", m.inputs[fVerifyKey], m.focusIdx == 1, acc) + "\n")
	b.WriteString(renderFieldAccent("Signature", m.inputs[fVerifySig], m.focusIdx == 2, acc) + "\n\n")
	b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top,
		renderButtonAccent("  Browse file  ", m.focusIdx == 3, acc),
		"   ",
		renderButtonAccent("  Browse key  ", m.focusIdx == 4, acc),
		"   ",
		renderButtonAccent("  Browse sig  ", m.focusIdx == 5, acc),
		"   ",
		renderButtonAccent("  Verify  ", m.focusIdx == 6, acc),
	) + "\n")
	b.WriteString(renderHelp())
	return styleApp.Render(b.String())
}

func (m Model) viewFilePicker() string {
	var b strings.Builder
	b.WriteString(accentTitle("Pick a file", colTeal) + "\n")
	b.WriteString(m.fp.View() + "\n")
	b.WriteString(styleHelp.Render("esc back  enter select"))
	return styleApp.Render(b.String())
}

func (m Model) viewResult() string {
	var b strings.Builder
	content := m.result.content
	// Wrap long single-line strings (e.g. base64 ciphertext) at 64 chars.
	if !strings.Contains(content, "\n") && len(content) > 64 {
		var wrapped strings.Builder
		for i, ch := range content {
			wrapped.WriteRune(ch)
			if (i+1)%64 == 0 && i+1 < len(content) {
				wrapped.WriteRune('\n')
			}
		}
		content = wrapped.String()
	}

	if m.result.isError {
		b.WriteString(styleError.Render("✗  "+m.result.title) + "\n\n")
		b.WriteString(styleResult.BorderForeground(colRose).Render(content) + "\n")
	} else {
		b.WriteString(styleSuccess.Render("✓  "+m.result.title) + "\n\n")
		b.WriteString(styleResult.BorderForeground(colGreen).Render(content) + "\n")
	}

	// Clipboard feedback
	if m.copied {
		b.WriteString("\n" + lipgloss.NewStyle().Foreground(colTeal).Bold(true).Render("✓ Copied to clipboard") + "\n")
	} else {
		b.WriteString("\n" + styleDim.Render("c copy to clipboard") + "\n")
	}

	b.WriteString(styleHelp.Render("enter / esc  back   q  main menu"))
	return styleApp.Render(b.String())
}

func (m Model) viewWorking() string {
	return styleApp.Render(
		"\n\n  " + m.spinner.View() + "  " + styleDim.Render("Working…"),
	)
}

// ---------------------------------------------------------------------------
// Render helpers (accent-aware)
// ---------------------------------------------------------------------------

func renderFieldAccent(label string, input textinput.Model, focused bool, accent lipgloss.TerminalColor) string {
	lbl := styleLabel.Render(label)
	var inp string
	if focused {
		inp = focusedInput(accent).Render(input.View())
	} else {
		inp = styleInput.Render(input.View())
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, lbl, inp)
}

func renderSelectorAccent(label string, options []string, idx int, focused bool, accent lipgloss.TerminalColor) string {
	lbl := styleLabel.Render(label)
	var parts []string
	for i, o := range options {
		if i == idx {
			if focused {
				parts = append(parts, accentSelector(accent).Render(o))
			} else {
				parts = append(parts, lipgloss.NewStyle().Bold(true).Padding(0, 1).Render(o))
			}
		} else {
			parts = append(parts, styleDim.Padding(0, 1).Render(o))
		}
	}
	row := strings.Join(parts, " ")
	if focused {
		row += styleDim.Render("  ← →")
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, lbl, row)
}

func renderToggleAccent(options []string, idx int, focused bool, accent lipgloss.TerminalColor) string {
	lbl := styleLabel.Render("Mode")
	var parts []string
	for i, o := range options {
		if i == idx {
			if focused {
				parts = append(parts, accentSelector(accent).Render(o))
			} else {
				parts = append(parts, lipgloss.NewStyle().Bold(true).Padding(0, 1).Render(o))
			}
		} else {
			parts = append(parts, styleDim.Padding(0, 1).Render(o))
		}
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, lbl, strings.Join(parts, " "))
}

func renderButtonAccent(label string, focused bool, accent lipgloss.TerminalColor) string {
	if focused {
		return accentButton(accent).Render(label)
	}
	return dimButton().Render(label)
}

func renderHelp() string {
	return styleHelp.Render("\ntab/↑↓ navigate  ← → select option  enter confirm  esc back")
}