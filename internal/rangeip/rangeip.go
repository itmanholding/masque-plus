package rangeip

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"net"
)

// ExpandCIDR returns n random IPs within the given CIDR.
func ExpandCIDR(cidr string, n int) ([]net.IP, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	res := make([]net.IP, 0, n)
	for len(res) < n {
		ip := randomIPInNet(ipnet)
		if ip == nil {
			continue
		}
		res = append(res, ip)
	}
	return res, nil
}

func randomIPInNet(ipnet *net.IPNet) net.IP {
	base := ipnet.IP
	if base.To4() != nil {
		mask := binary.BigEndian.Uint32(ipnet.Mask)
		start := binary.BigEndian.Uint32(base.To4()) & mask
		size := ^mask
		if size <= 2 {
			b := make(net.IP, 4)
			copy(b, base.To4())
			return b
		}
		max := int64(size - 1)
		idx, _ := rand.Int(rand.Reader, big.NewInt(max))
		val := start + 1 + uint32(idx.Int64())
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, val)
		return net.IP(buf)
	}
	ones, _ := ipnet.Mask.Size()
	width := 128 - ones
	if width <= 0 {
		return base
	}
	max := new(big.Int).Lsh(big.NewInt(1), uint(width))
	idx, _ := rand.Int(rand.Reader, max)
	baseInt := new(big.Int).SetBytes(base)
	cand := new(big.Int).Add(baseInt, idx)
	b := cand.Bytes()
	if len(b) < 16 {
		p := make([]byte, 16)
		copy(p[16-len(b):], b)
		b = p
	}
	return net.IP(b)
}
