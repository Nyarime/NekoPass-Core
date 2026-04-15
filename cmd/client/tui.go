package main

import (
	"fmt"
	"time"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// 配色
var (
	colorPrimary = lipgloss.Color("#00D1FF")
	colorAccent  = lipgloss.Color("#FF2D92")
	colorSuccess = lipgloss.Color("#00FF9D")
	colorError   = lipgloss.Color("#FF4D4D")
	colorMuted   = lipgloss.Color("#6C7086")
	colorBg      = lipgloss.Color("#1E1E2E")
	colorFg      = lipgloss.Color("#CDD6F4")

	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorPrimary).
			Background(lipgloss.Color("#181825")).
			Padding(0, 1)

	statusStyle = lipgloss.NewStyle().
			Foreground(colorFg).
			Background(lipgloss.Color("#181825")).
			Padding(0, 1)

	activeTab = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorBg).
			Background(colorPrimary).
			Padding(0, 1)

	inactiveTab = lipgloss.NewStyle().
			Foreground(colorMuted).
			Padding(0, 1)

	boxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#313244")).
			Padding(0, 1)

	logStyle = lipgloss.NewStyle().
			Foreground(colorMuted)

	connStyle = lipgloss.NewStyle().
			Foreground(colorSuccess)
)

type tickMsg time.Time

type tuiModel struct {
	width    int
	height   int
	tab      int
	logs     []string
	conns    int
	speed    string
	tunOn    bool
	proxyOn  bool
	mode     string
	server   string
	quitting bool
}

func newTUIModel() tuiModel {
	return tuiModel{
		tab:     0,
		logs:    []string{"运行中"},
		mode:    config.Mode,
		server:  config.Server,
		proxyOn: true,
	}
}

func (m tuiModel) Init() tea.Cmd {
	return tea.Batch(tickCmd(), tea.EnterAltScreen)
}

func tickCmd() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		case "1":
			m.tab = 0
		case "2":
			m.tab = 1
		case "3":
			m.tab = 2
		case "left":
			if m.tab > 0 { m.tab-- }
		case "right":
			if m.tab < 3 { m.tab++ }
		case "l":
			m.tab = 3 // Log视图
		case "b":
			if m.tab == 3 { m.tab = 0 } // 返回Dashboard
		case "t":
			m.tunOn = !m.tunOn
			if m.tunOn {
				m.logs = append(m.logs, fmt.Sprintf("[%s] TUN 已开启", time.Now().Format("15:04:05")))
			} else {
				m.logs = append(m.logs, fmt.Sprintf("[%s] TUN 已关闭", time.Now().Format("15:04:05")))
			}
		case "s":
			m.proxyOn = !m.proxyOn
			if m.proxyOn {
				m.logs = append(m.logs, fmt.Sprintf("[%s] 系统代理 已开启", time.Now().Format("15:04:05")))
			} else {
				m.logs = append(m.logs, fmt.Sprintf("[%s] 系统代理 已关闭", time.Now().Format("15:04:05")))
			}
		case "m":
			switch m.mode {
			case "rule":
				m.mode = "global"
			case "global":
				m.mode = "direct"
			default:
				m.mode = "rule"
			}
			m.logs = append(m.logs, fmt.Sprintf("[%s] 模式: %s", time.Now().Format("15:04:05"), m.mode))
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tickMsg:
		m.conns = int(proxyConns.Load()) + len(connTrack.conns)
		return m, tickCmd()
	}

	return m, nil
}

func (m tuiModel) View() string {
	if m.quitting {
		return ""
	}

	w := m.width
	if w == 0 {
		w = 80
	}
	h := m.height
	if h == 0 {
		h = 24
	}

	// Header
	tunStatus := lipgloss.NewStyle().Foreground(colorError).Render("● TUN OFF")
	if m.tunOn {
		tunStatus = lipgloss.NewStyle().Foreground(colorSuccess).Render("● TUN ON")
	}
	header := titleStyle.Width(w).Render(
		fmt.Sprintf("NekoPass Lite  %s  → %s", tunStatus, m.server))

	// Tabs
	tabs := []string{"Dashboard", "Connections", "Config", "Log"}
	tabRow := ""
	for i, t := range tabs {
		if i == m.tab {
			tabRow += activeTab.Render(t) + " "
		} else {
			tabRow += inactiveTab.Render(t) + " "
		}
	}

	// Main content
	var content string
	switch m.tab {
	case 0: // Dashboard
		proxyIcon := "●"
		proxyColor := colorSuccess
		if !m.proxyOn {
			proxyColor = colorError
		}

		content = boxStyle.Width(w - 4).Render(
			lipgloss.JoinVertical(lipgloss.Left,
				lipgloss.NewStyle().Bold(true).Render("状态"),
				"",
				fmt.Sprintf("  服务器:    %s", m.server),
				fmt.Sprintf("  模式:      %s", lipgloss.NewStyle().Foreground(colorPrimary).Render(m.mode)),
				fmt.Sprintf("  系统代理:  %s", lipgloss.NewStyle().Foreground(proxyColor).Render(proxyIcon)),
				fmt.Sprintf("  连接数:    %s", connStyle.Render(fmt.Sprintf("%d", m.conns))),
				"",
				lipgloss.NewStyle().Bold(true).Render("快捷键"),
				"",
				"  T  切换TUN    S  系统代理    M  模式切换",
				"  1-3 切换页面   Q  退出",
			))

	case 1: // Connections + FEC/SACK Metrics
		var fecInfo, transportInfo string
		if s := bridge.GetFECStats(); s != nil {
			fecInfo = fmt.Sprintf(
				"  FEC Parity:     %d\n"+
				"  FEC 有效性:     %.1f%%%%\n"+
				"  FEC 恢复:       %d/%d\n"+
				"  丢包率:         %.1f%%%%\n"+
				"  RTT:            %s\n"+
				"  Jitter:         %s\n"+
				"  重传队列:       %d\n"+
				"  MTU:            %d",
				s.Parity, s.Effectiveness*100,
				s.Recovered, s.Decodes,
				s.LossRate*100, s.RTT, s.Jitter,
				s.RetransmitQ, s.MTU)
		} else {
			fecInfo = "  (NRUP未连接)"
		}
		if transport.udpAvailable.Load() {
			transportInfo = "✅ UDP (NRUP)"
		} else {
			transportInfo = "⚠️ TCP (NRTP)"
		}
		content = boxStyle.Width(w - 4).Render(
			lipgloss.JoinVertical(lipgloss.Left,
				lipgloss.NewStyle().Bold(true).Render("📊 传输状态"),
				"",
				fmt.Sprintf("  活跃连接:     %d", m.conns),
				fmt.Sprintf("  传输模式:     %s", transportInfo),
				"",
				lipgloss.NewStyle().Bold(true).Render("FEC / SACK"),
				"",
				fecInfo,
			))

	case 2: // Config
		content = boxStyle.Width(w - 4).Render(
			lipgloss.JoinVertical(lipgloss.Left,
				lipgloss.NewStyle().Bold(true).Render("配置"),
				"",
				fmt.Sprintf("  server:       %s", m.server),
				fmt.Sprintf("  mode:         %s", m.mode),
				fmt.Sprintf("  system_proxy: %v", m.proxyOn),
				fmt.Sprintf("  tun:          %v", m.tunOn),
			))
	}

	// 底部只显示最新1条日志
	var lastLog string
	if logs := getTUILogs(); len(logs) > 0 {
		lastLog = logs[len(logs)-1]
	} else {
		lastLog = "运行中"
	}
	logContent := logStyle.Width(w - 4).Render(lastLog)

	// Status bar
	statusBar := statusStyle.Width(w).Render(
		fmt.Sprintf(" %s:%s • %d conn • mode:%s",
			"127.0.0.1", extractPort(config.Proxy.Listen),
			m.conns, m.mode))

	return lipgloss.JoinVertical(lipgloss.Left,
		header,
		tabRow,
		content,
		logContent,
		statusBar,
	)
}

func startTUI() {
	p := tea.NewProgram(newTUIModel(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Printf("TUI error: %v\n", err)
	}
}
