package main

import "github.com/charmbracelet/lipgloss"

// Color palette — derived from the ID-Spoofer logo:
// dark navy background, bright cyan/blue accents, teal highlights.
var (
	colorBlue      = lipgloss.Color("#0077b6")
	colorCyan      = lipgloss.Color("#00b4d8")
	colorLightCyan = lipgloss.Color("#48cae4")
	colorWhite     = lipgloss.Color("#caf0f8")
	colorDim       = lipgloss.Color("#577590")
	colorGreen     = lipgloss.Color("#06d6a0")
	colorYellow    = lipgloss.Color("#ffd166")
	colorRed       = lipgloss.Color("#ef476f")
	colorOrange    = lipgloss.Color("#f77f00")
)

// ── Top-level layout ────────────────────────────────────────────────────────

var (
	sTitle = lipgloss.NewStyle().
		Bold(true).
		Foreground(colorCyan)

	sSubtitle = lipgloss.NewStyle().
			Foreground(colorDim)

	sBanner = lipgloss.NewStyle().
		Border(lipgloss.DoubleBorder()).
		BorderForeground(colorBlue).
		Padding(0, 2)

	sHelpBar = lipgloss.NewStyle().
			Foreground(colorDim)
)

// ── Tab bar ─────────────────────────────────────────────────────────────────

var (
	sTabActive = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorCyan).
			Border(lipgloss.NormalBorder(), false, false, true, false).
			BorderForeground(colorCyan).
			Padding(0, 2)

	sTabInactive = lipgloss.NewStyle().
			Foreground(colorDim).
			Padding(0, 2)

	sTabBar = lipgloss.NewStyle().
		Border(lipgloss.NormalBorder(), false, false, true, false).
		BorderForeground(colorBlue)
)

// ── Section headers ─────────────────────────────────────────────────────────

var (
	sSectionTitle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorLightCyan)

	sSeparator = lipgloss.NewStyle().
			Foreground(colorBlue)
)

// ── Checkboxes / radio ──────────────────────────────────────────────────────

var (
	sChecked = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorGreen)

	sUnchecked = lipgloss.NewStyle().
			Foreground(colorDim)

	sCursor = lipgloss.NewStyle().
		Bold(true).
		Foreground(colorCyan)

	sItemLabel = lipgloss.NewStyle().
			Foreground(colorWhite)
)

// ── Description panel ───────────────────────────────────────────────────────

var (
	sDescTitle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorCyan)

	sDescBody = lipgloss.NewStyle().
			Foreground(colorWhite).
			Width(44)

	sDescBox = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorBlue).
			Padding(0, 1)
)

// ── Status indicators ───────────────────────────────────────────────────────

var (
	sOK = lipgloss.NewStyle().
		Bold(true).
		Foreground(colorGreen)

	sFail = lipgloss.NewStyle().
		Bold(true).
		Foreground(colorRed)

	sWarn = lipgloss.NewStyle().
		Bold(true).
		Foreground(colorYellow)

	sSpoofed = lipgloss.NewStyle().
			Foreground(colorOrange)

	sUp = lipgloss.NewStyle().
		Bold(true).
		Foreground(colorGreen)

	sDown = lipgloss.NewStyle().
		Foreground(colorRed)

	sUnavail = lipgloss.NewStyle().
			Foreground(colorDim).
			Italic(true)
)

// ── Dashboard panels ────────────────────────────────────────────────────────

var (
	sPanel = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colorBlue).
		Padding(0, 1)

	sPanelTitle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorLightCyan)

	sWarningBox = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorYellow).
			Padding(0, 1)

	sTableHeader = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorLightCyan)

	sTableRow = lipgloss.NewStyle().
			Foreground(colorWhite)

	sTableDim = lipgloss.NewStyle().
			Foreground(colorDim)
)
