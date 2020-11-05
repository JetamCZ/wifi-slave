from radiotap import radiotap as r, pcap


pc = pcap.pcap(name='foo.pcap')
tstamp, pkt = pc[0]
off, radiotap = r.radiotap_parse(pkt)
off, mac = r.ieee80211_parse(pkt, off)