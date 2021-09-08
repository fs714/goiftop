package decoder

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"reflect"
)

func NewLayerDecoder(decodingLayers ...gopacket.DecodingLayer) *LayerDecoder {
	ld := &LayerDecoder{
		DecodingLayerMap: make(map[gopacket.LayerType]gopacket.DecodingLayer),
	}

	for _, dl := range decodingLayers {
		ld.PutDecodingLayer(dl)
	}

	ld.df = ld

	return ld
}

type LayerDecoder struct {
	DecodingLayerMap map[gopacket.LayerType]gopacket.DecodingLayer
	df               gopacket.DecodeFeedback
	Truncated        bool
}

func (ld *LayerDecoder) SetTruncated() {
	ld.Truncated = true
}

func (ld *LayerDecoder) PutDecodingLayer(d gopacket.DecodingLayer) {
	for _, layerType := range d.CanDecode().LayerTypes() {
		ld.DecodingLayerMap[layerType] = d
	}
}

func (ld *LayerDecoder) GetDecodingLayerByType(layerType gopacket.LayerType) (gopacket.DecodingLayer, bool) {
	d, ok := ld.DecodingLayerMap[layerType]
	return d, ok
}

func (ld *LayerDecoder) GetFirstLayerType(linkType layers.LinkType) gopacket.LayerType {
	for k, _ := range ld.DecodingLayerMap {
		f1 := layers.LinkTypeMetadata[linkType].DecodeWith
		f2 := gopacket.DecodersByLayerName[k.String()]

		if reflect.ValueOf(f1) == reflect.ValueOf(f2) {
			return k
		}
	}

	return gopacket.LayerTypeZero
}

func (ld *LayerDecoder) DecodeLayers(data []byte, firstLayer gopacket.LayerType, decoded *[]gopacket.LayerType) error {
	ld.Truncated = false

	layerType, err := ld.Decoder(data, firstLayer, decoded)
	if layerType != gopacket.LayerTypeZero {
		return gopacket.UnsupportedLayerType(layerType)
	}

	return err
}

func (ld *LayerDecoder) Decoder(data []byte, firstLayer gopacket.LayerType, decoded *[]gopacket.LayerType) (gopacket.LayerType, error) {
	*decoded = (*decoded)[:0]
	layerType := firstLayer
	decoder, ok := ld.GetDecodingLayerByType(firstLayer)
	if !ok {
		return firstLayer, nil
	}

	for {
		err := decoder.DecodeFromBytes(data, ld.df)
		if err != nil {
			return gopacket.LayerTypeZero, err
		}

		*decoded = append(*decoded, layerType)
		nextLayerType := decoder.NextLayerType()

		// By default, IPv4 layer will decode fragmented packet to Segment layer.
		// To statistic fragmented packet, the first IPv4 layer payload will be decoded
		if layerType == layers.LayerTypeIPv4 {
			ipv4DecodingLayer, _ := ld.GetDecodingLayerByType(layers.LayerTypeIPv4)
			ipv4Layer := ipv4DecodingLayer.(*layers.IPv4)
			if ipv4Layer.Flags&layers.IPv4MoreFragments == 1 && ipv4Layer.FragOffset == 0 {
				nextLayerType = ipv4Layer.Protocol.LayerType()
			}
		}

		layerType = nextLayerType

		data = decoder.LayerPayload()
		if len(data) == 0 {
			break
		}

		decoder, ok = ld.GetDecodingLayerByType(layerType)
		if !ok {
			return layerType, nil
		}
	}

	return gopacket.LayerTypeZero, nil
}
