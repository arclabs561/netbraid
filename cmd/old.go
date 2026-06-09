package cmd

// rootCmd.Flags().StringP("config", "c", "config.toml", "toml file to trigger config")
// rootCmd.Flags().StringSliceP("only", "o", nil, "config trigger names to only run")
// rootCmd.Flags().StringP("iface", "i", "", "which network interface to use, if not first active")
// rootCmd.Flags().StringP("pcap", "p", "", "whether to read from pcap file instead of live interface")

// func oldRootRunE(cmd *cobra.Command, args []string) error {
// 	ctx := cmd.Context()
// 	ctx = initLogger(ctx, cmd, args)

// 	var subs []watch.Subscriber
// 	path := mustString(cmd, "config")
// 	only := mustStringSlice(cmd, "only")
// 	if path != "" {
// 		sub, err := watch.NewSubConfig(path, only)
// 		if err != nil {
// 			return err
// 		}
// 		subs = append(subs, sub)
// 	}

// 	iface := mustString(cmd, "iface")
// 	pcap := mustString(cmd, "pcap")
// 	if iface != "" && pcap != "" {
// 		return errors.Errorf(
// 			"cannot specify both --iface=%s or --pcap=%s",
// 			iface,
// 			pcap,
// 		)
// 	}

// 	w := watch.NewWatcher(subs...)
// 	if pcap != "" {
// 		return w.WatchPCAP(ctx, pcap)
// 	}
// 	if iface == "" {
// 		var err error
// 		iface, err = monitor.FirstInterface()
// 		if err != nil {
// 			return err
// 		}
// 		log.Info().Msgf("using first up interface: %s", iface)
// 	}
// 	return w.WatchLive(ctx, iface)
// }

// func NewMonitor(
// 	cmd *cobra.Command,
// 	args []string,
// ) (*Monitor, error) {
// 	quiet, err := cmd.Flags().GetBool("quiet")
// 	if err != nil {
// 		panic(err)
// 	}
// 	autostopRaw := mustString(cmd, "auto-stop")
// 	// sane defaults
// 	var (
// 		autostopDur = 10 * time.Second
// 		tickerDur   = 1 * time.Second
// 	)
// 	{
// 		parts := strings.Split(autostopRaw, ":")
// 		if len(parts) != 2 {
// 			return nil, fmt.Errorf("invalid --autostop, must be of form test:value, got: %q", autostopRaw)
// 		}
// 		switch part := strings.ToLower(parts[0]); part {
// 		case "duration", "dur":
// 			d, err := time.ParseDuration(parts[1])
// 			if err != nil {
// 				return nil, fmt.Errorf("failed to part as duration %q: %w", parts[1], err)
// 			}
// 			autostopDur = d
// 		case "count":
// 			panic(fmt.Sprintf("unimplemented: %s", part))
// 		case "filesize", "size":
// 			panic(fmt.Sprintf("unimplemented: %s", part))
// 		default:
// 			return nil, fmt.Errorf("invalid --autostop, test: %q", part)
// 		}
// 	}
// 	log.Info().Msgf("using autostop dur: %v", autostopDur)
// 	return &Monitor{
// 		quiet:       quiet,
// 		autostopDur: autostopDur,
// 		tickerDur:   tickerDur,
// 	}, nil
// }

// func (m *Monitor) ListenInterface(
// 	agg *aggregator,
// 	iface string,
// 	hopper ChannelHopper,
// ) error {
// 	var err error
// 	h, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
// 	if err != nil {
// 		return err
// 	}

// 	var app *tview.Application
// 	var textView *tview.TextView
// 	if !m.quiet {
// 		app = tview.NewApplication()
// 		textView = tview.NewTextView()
// 		textView.SetChangedFunc(func() {
// 			app.Draw()
// 		})
// 		app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
// 			if event.Key() == tcell.KeyCtrlC {
// 				app.Stop()
// 			}
// 			return event
// 		})
// 	}

// 	pcapFile := fmt.Sprintf("%s.pcap", iface)
// 	log.Info().Msgf("writing pcap to %s", pcapFile)
// 	pw, err := NewPcapWriter(pcapFile)
// 	if err != nil {
// 		return fmt.Errorf("failed to create pcap writer: %w", err)
// 	}
// 	defer func() {
// 		log.Debug().Msgf("closing pcap writer: %s", pcapFile)
// 		pw.Close()
// 	}()

// 	hopsFile := fmt.Sprintf("%s.csv", iface)
// 	f, err := os.Create(hopsFile)
// 	if err != nil {
// 		return fmt.Errorf("failed to create hops file: %w", err)
// 	}
// 	defer f.Close()
// 	g := csv.NewWriter(f)
// 	headers := []string{
// 		"channel",
// 		"begin_time",
// 		"end_time",
// 	}
// 	if err := g.Write(headers); err != nil {
// 		return fmt.Errorf("failed to write header to hops file: %w", err)
// 	}
// 	defer func() {
// 		log.Debug().Msgf("flushing hops file: %s", hopsFile)
// 		g.Flush()
// 		if err := g.Error(); err != nil {
// 			log.Warn().Msgf("failed to flush hops file: %v", err)
// 		}
// 	}()

// 	wg := new(sync.WaitGroup)
// 	wg.Add(1)
// 	go func() {
// 		defer wg.Done()
// 		if !m.quiet {
// 			defer app.Stop()
// 		}
// 		go hopper.Start(func(info HopInfo) {
// 			err := g.Write([]string{
// 				fmt.Sprintf("%d", info.Channel),
// 				info.Begin.Format(time.RFC3339Nano),
// 				info.End.Format(time.RFC3339Nano),
// 			})
// 			if err != nil {
// 				log.Warn().Msgf("failed to write to hops file: %v", err)
// 			}
// 		})
// 		defer func() {
// 			if err := hopper.Stop(); err != nil {
// 				log.Err(err).Msg("failed to stop hopper")
// 			}
// 		}()
// 		src := gopacket.NewPacketSource(h, h.LinkType())
// 		i := -1
// 		packets := src.Packets()
// 		timeout := time.NewTimer(m.autostopDur)
// 		defer timeout.Stop()
// 		display := time.NewTicker(m.tickerDur)
// 		for {
// 			select {
// 			case <-timeout.C:
// 				return
// 			case <-display.C:
// 				if m.quiet {
// 					continue
// 				}
// 				app.QueueUpdateDraw(func() {
// 					textView.Clear()
// 					if _, err := fmt.Fprint(textView, agg.summarize(20)); err != nil {
// 						log.Error().Err(err).Msg("failed to write summary")
// 					}
// 				})
// 			case p := <-packets:
// 				// scapy-inspired packet.summary()
// 				// "RadioTap / Dot11FCS / Dot11Beacon / ...
// 				var packetSummary bytes.Buffer
// 				packetSummary.WriteString(fmt.Sprintf("Packet(i=%d, bytes=%d, layers=%d) ", i, len(p.Data()), len(p.Layers())))
// 				var prevLayerType string
// 				var run int
// 				for i, l := range p.Layers() {
// 					ty := l.LayerType().String()
// 					if ty == prevLayerType {
// 						run++
// 						if i == len(p.Layers())-1 {
// 							packetSummary.WriteString(fmt.Sprintf(" (%d)", run+1))
// 						}
// 						continue
// 					}
// 					prevLayerType = ty
// 					if i > 0 {
// 						packetSummary.WriteString(" / ")
// 					}
// 					packetSummary.WriteString(ty)
// 					if run > 0 {
// 						packetSummary.WriteString(fmt.Sprintf(" (%d)", run+1))
// 					}
// 					run = 0
// 				}
// 				i++
// 				log.Trace().Msgf("packet: %s", packetSummary.String())
// 				if err := pw.Write(p); err != nil {
// 					log.Err(err).Msg("failed to write packet")
// 					continue
// 				}
// 				a := analyzePacket(p)
// 				if a != nil {
// 					agg.add(a)
// 				}
// 			}
// 		}
// 	}()

// 	if !m.quiet {
// 		wg.Add(1)
// 		go func() {
// 			defer wg.Done()
// 			if err := app.SetRoot(textView, true).Run(); err != nil {
// 				log.Err(err).Msg("failed to run app")
// 			}
// 		}()
// 	}

// 	wg.Wait()
// 	return nil
// }

// func hopUntil(
// 	agg *aggregator,
// 	iface string,
// 	interval time.Duration,
// 	done <-chan struct{},
// 	sampler chSampler,
// 	fn func(info HopInfo),
// ) {
// 	prevCh := mo.None[uint8]()
// 	step := func(ch uint8) (info *HopInfo, err error) {
// 		begin := time.Now()
// 		var aggCount int
// 		chCounts := make(map[uint8]int)
// 		agg.setOnAdd(func(a *AnalyzedPacket) {
// 			aggCount++
// 			chCounts[a.Channel]++
// 		})
// 		defer func() {
// 			agg.mu.Lock()
// 			defer agg.mu.Unlock()

// 			log := log.Debug().Uint8("ch", ch).
// 				Int("packets", aggCount).
// 				Str("iface", iface).
// 				Str("ch", sprintOrdered(chCounts, -1)).
// 				Int("step", agg.global.step).
// 				Str("dur", fmt.Sprintf("%v", interval))
// 			if err == nil {
// 				diff := info.End.Sub(info.Begin) - interval
// 				log = log.Str("diff", fmt.Sprintf("%v", diff.Round(time.Microsecond)))
// 			}
// 			log.Msg("dwell interval")

// 			agg.global.step++
// 			agg.modChNoSync(ch, func(info *channelInfo) {
// 				info.directSamples++
// 			})
// 			for adjCh := range chCounts {
// 				if adjCh != ch {
// 					agg.modChNoSync(adjCh, func(info *channelInfo) {
// 						info.adjacentSamples += 1
// 					})
// 				}
// 			}
// 			agg.unsetOnAddNoSync()
// 		}()
// 		if prev, ok := prevCh.Get(); !ok || ch != prev {
// 			log.Debug().Msgf("setting channel to %d on on %s", ch, iface)
// 			if err := setChannel(iface, ch); err != nil {
// 				return nil, fmt.Errorf("failed to set channel: %w", err)
// 			}
// 			prevCh = mo.Some(ch)
// 		}

// 		time.Sleep(interval)

// 		return &HopInfo{
// 			Channel:    ch,
// 			Begin:      begin,
// 			End:        time.Now(),
// 			RecvCounts: chCounts,
// 		}, nil
// 	}
// 	for {
// 		var stop bool
// 		select {
// 		case <-done:
// 			stop = true
// 		default:
// 		}
// 		if stop {
// 			return
// 		}
// 		ch, params, obs := sampler.Sample()
// 		info, err := step(ch)
// 		if err != nil {
// 			log.Err(err).Msgf("failed to hop: %v", err)
// 			continue
// 		}
// 		fn(*info)
// 		obs(*info)
// 		agg.modCh(ch, func(info *channelInfo) {
// 			info.params = params
// 		})
// 	}
// }

// func (a *aggregator) add(p *AnalyzedPacket) {
// 	a.mu.Lock()
// 	defer a.mu.Unlock()

// 	if a.onAdd != nil {
// 		defer a.onAdd(p)
// 	}

// 	a.global.packets++

// 	a.modChNoSync(p.Channel, func(info *channelInfo) {
// 		info.channel = p.Channel
// 		info.lastSeen = p.ObservedAt
// 		info.packets++
// 	})

// 	a.modSrcNoSync(p.Src.String(), func(info *sourceInfo) {
// 		info.src = p.Src
// 		info.lastSeen = p.ObservedAt
// 		info.packets++
// 		// info.signalsMean.Add(float64(p.DbmSignal))
// 		// info.signalsStd.Add(float64(p.DbmSignal))
// 		info.types[p.Dot11Type.String()]++
// 		info.channels[fmt.Sprintf("%d", p.Channel)]++
// 	})

// }
