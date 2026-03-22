package tui

import "github.com/charmbracelet/lipgloss"

// Palette — vivid but consistent across light and dark terminals.
var (
	colPurple = lipgloss.AdaptiveColor{Light: "#6C4FF6", Dark: "#9D7FF4"}
	colTeal   = lipgloss.AdaptiveColor{Light: "#0F9B8E", Dark: "#2DD4BF"}
	colAmber  = lipgloss.AdaptiveColor{Light: "#B45309", Dark: "#FBB73C"}
	colRose   = lipgloss.AdaptiveColor{Light: "#BE185D", Dark: "#FB7185"}
	colBlue   = lipgloss.AdaptiveColor{Light: "#1D4ED8", Dark: "#60A5FA"}
	colGreen  = lipgloss.AdaptiveColor{Light: "#15803D", Dark: "#4ADE80"}

	colFg    = lipgloss.AdaptiveColor{Light: "#1a1a1a", Dark: "#f0f0f0"}
	colFgMid = lipgloss.AdaptiveColor{Light: "#555555", Dark: "#aaaaaa"}
	colFgDim = lipgloss.AdaptiveColor{Light: "#999999", Dark: "#555555"}

	// Per-screen accent colours.
	accentEncrypt = colPurple
	accentDecrypt = colTeal
	accentHash    = colAmber
	accentKeygen  = colBlue
	accentEncode  = colRose
	accentSign    = colGreen
	accentVerify  = colGreen

	// Layout
	styleApp = lipgloss.NewStyle().Padding(2, 3)

	styleTitle = lipgloss.NewStyle().
			Bold(true).
			Padding(0, 1).
			MarginBottom(1)

	// Form
	styleLabel = lipgloss.NewStyle().
			Foreground(colFgMid).
			Width(18)

	styleInput = lipgloss.NewStyle().
			Foreground(colFg).
			Border(lipgloss.NormalBorder(), false, false, true, false).
			BorderForeground(colFgDim).
			Width(44)

	// Status / result
	styleSuccess = lipgloss.NewStyle().
			Bold(true).
			Foreground(colGreen)

	styleError = lipgloss.NewStyle().
			Bold(true).
			Foreground(colRose)

	styleDim = lipgloss.NewStyle().
			Foreground(colFgDim)

	styleResult = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			Padding(0, 1).
			MaxWidth(80)

	// Help bar
	styleHelp = lipgloss.NewStyle().
			Foreground(colFgDim).
			MarginTop(1)

	// File picker path
	stylePath = lipgloss.NewStyle().
			Foreground(colTeal).
			Italic(true)
)

// accentTitle renders a screen title with its designated accent colour.
func accentTitle(label string, col lipgloss.TerminalColor) string {
	return styleTitle.
		Background(col).
		Foreground(lipgloss.Color("#ffffff")).
		Render("  " + label + "  ")
}

// accentInput returns a focused input style using the screen's accent colour.
func focusedInput(accent lipgloss.TerminalColor) lipgloss.Style {
	return styleInput.
		BorderForeground(accent).
		Foreground(colFg)
}

// accentButton returns a focused button style using the screen's accent colour.
func accentButton(accent lipgloss.TerminalColor) lipgloss.Style {
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(accent).
		Foreground(accent).
		Bold(true).
		Padding(0, 1)
}

func dimButton() lipgloss.Style {
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colFgDim).
		Foreground(colFgMid).
		Padding(0, 1)
}

func accentSelector(accent lipgloss.TerminalColor) lipgloss.Style {
	return lipgloss.NewStyle().
		Bold(true).
		Background(accent).
		Foreground(lipgloss.Color("#ffffff")).
		Padding(0, 1)
}