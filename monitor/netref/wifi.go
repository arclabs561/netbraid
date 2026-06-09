package netref

import (
	"sort"
)

// Channel number to center frequency (MHz) mapping.
// https://en.wikipedia.org/wiki/List_of_WLAN_channels
var ChanToFreq = map[int]int{
	1:   2412,
	2:   2417,
	3:   2422,
	4:   2427,
	5:   2432,
	6:   2437,
	7:   2442,
	8:   2447,
	9:   2452,
	10:  2457,
	11:  2462,
	12:  2467,
	13:  2472,
	14:  2484,
	32:  5160,
	34:  5170,
	36:  5180,
	38:  5190,
	40:  5200,
	42:  5210,
	44:  5220,
	46:  5230,
	48:  5240,
	50:  5250,
	52:  5260,
	54:  5270,
	56:  5280,
	58:  5290,
	60:  5300,
	62:  5310,
	64:  5320,
	66:  5330,
	68:  5340,
	70:  5350,
	72:  5360,
	74:  5370,
	76:  5380,
	78:  5390,
	80:  5400,
	82:  5410,
	84:  5420,
	86:  5430,
	88:  5440,
	90:  5450,
	92:  5460,
	94:  5470,
	96:  5480,
	98:  5490,
	100: 5500,
	102: 5510,
	104: 5520,
	106: 5530,
	108: 5540,
	110: 5550,
	112: 5560,
	114: 5570,
	116: 5580,
	118: 5590,
	120: 5600,
	122: 5610,
	124: 5620,
	126: 5630,
	128: 5640,
	132: 5660,
	134: 5670,
	136: 5680,
	138: 5690,
	140: 5700,
	142: 5710,
	144: 5720,
	149: 5745,
	151: 5755,
	153: 5765,
	155: 5775,
	157: 5785,
	159: 5795,
	161: 5805,
	165: 5825,
}

var FrequencyToChannel map[int]int
var IndexToChannel map[int]int
var ChannelToIndex map[int]int

func init() {
	FrequencyToChannel = make(map[int]int)
	for ch, freq := range ChanToFreq {
		FrequencyToChannel[freq] = ch
	}

	IndexToChannel = make(map[int]int)
	ChannelToIndex = make(map[int]int)
	var ordered []int
	for ch := range ChanToFreq {
		ordered = append(ordered, ch)
	}
	sort.Ints(ordered)
	for i, ch := range ordered {
		IndexToChannel[i] = ch
		ChannelToIndex[ch] = i
	}
}

type Band int

const (
	Band2_4GHz Band = iota
	Band5GHz
)

var BandToChannels = map[Band][]int{
	Band2_4GHz: {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14},
	Band5GHz:   {32, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62, 64, 68, 96, 100, 102, 104, 106, 108, 110, 112, 114, 116, 118, 120, 122, 124, 126, 128, 132, 134, 136, 138, 140, 142, 144, 151, 153, 155, 157, 159, 161, 163, 165, 167, 169, 171, 173, 175, 177},
}
