package nodeagent

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding"

	"mgb-panel/internal/model"
	"mgb-panel/internal/topology"
)

const singboxStatsAddress = "127.0.0.1:10085"

type v2rayStatsCodec struct{}

func (v2rayStatsCodec) Name() string { return "proto" }

func (v2rayStatsCodec) Marshal(v any) ([]byte, error) {
	msg, ok := v.(proto.Message)
	if !ok {
		return nil, fmt.Errorf("stats request is not proto message")
	}
	return proto.Marshal(msg)
}

func (v2rayStatsCodec) Unmarshal(data []byte, v any) error {
	msg, ok := v.(proto.Message)
	if !ok {
		return fmt.Errorf("stats response is not proto message")
	}
	return proto.Unmarshal(data, msg)
}

type queryStatsRequest struct {
	Pattern string `protobuf:"bytes,1,opt,name=pattern,proto3" json:"pattern,omitempty"`
	Reset   bool   `protobuf:"varint,2,opt,name=reset,proto3" json:"reset,omitempty"`
}

func (*queryStatsRequest) Reset()         {}
func (*queryStatsRequest) ProtoMessage()  {}
func (m *queryStatsRequest) String() string { return proto.CompactTextString(m) }

type queryStatsResponse struct {
	Stat []*stat `protobuf:"bytes,1,rep,name=stat,proto3" json:"stat,omitempty"`
}

func (*queryStatsResponse) Reset()         {}
func (*queryStatsResponse) ProtoMessage()  {}
func (m *queryStatsResponse) String() string { return proto.CompactTextString(m) }

type stat struct {
	Name  string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Value int64  `protobuf:"varint,2,opt,name=value,proto3" json:"value,omitempty"`
}

func (*stat) Reset()         {}
func (*stat) ProtoMessage()  {}
func (m *stat) String() string { return proto.CompactTextString(m) }

func init() {
	encoding.RegisterCodec(v2rayStatsCodec{})
}

func collectTraffic(ctx context.Context, nodeID string) ([]model.TrafficAggregate, error) {
	if nodeID == "" {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, singboxStatsAddress, grpc.WithInsecure(), grpc.WithBlock(), grpc.WithDefaultCallOptions(grpc.ForceCodec(v2rayStatsCodec{})))
	if err != nil {
		return nil, fmt.Errorf("connect sing-box stats api: %w", err)
	}
	defer conn.Close()

	var resp queryStatsResponse
	if err := conn.Invoke(ctx, "/v2ray.core.app.stats.command.StatsService/QueryStats", &queryStatsRequest{Pattern: "", Reset: true}, &resp); err != nil {
		return nil, fmt.Errorf("query sing-box stats: %w", err)
	}
	return trafficFromStats(nodeID, resp.Stat), nil
}

func trafficFromStats(nodeID string, stats []*stat) []model.TrafficAggregate {
	byKey := make(map[string]*model.TrafficAggregate)
	add := func(userID, inboundID, direction string, value int64) {
		if value == 0 {
			return
		}
		key := nodeID + "\x00" + userID + "\x00" + inboundID
		item := byKey[key]
		if item == nil {
			item = &model.TrafficAggregate{NodeID: nodeID, UserID: userID, InboundID: inboundID}
			byKey[key] = item
		}
		switch direction {
		case "uplink":
			item.Uplink += value
		case "downlink":
			item.Downlink += value
		}
	}

	for _, item := range stats {
		if item == nil || item.Value == 0 {
			continue
		}
		parts := strings.Split(item.Name, ">>>")
		if len(parts) < 4 || parts[len(parts)-2] != "traffic" {
			continue
		}
		direction := parts[len(parts)-1]
		switch parts[0] {
		case "user":
			userID, inboundID, ok := topology.ParseTrafficUserTag(parts[1])
			if ok {
				add(userID, inboundID, direction, item.Value)
				add(userID, "", direction, item.Value)
			}
		case "inbound":
			add("", parts[1], direction, item.Value)
			add("", "", direction, item.Value)
		}
	}

	out := make([]model.TrafficAggregate, 0, len(byKey))
	for _, item := range byKey {
		out = append(out, *item)
	}
	return out
}
