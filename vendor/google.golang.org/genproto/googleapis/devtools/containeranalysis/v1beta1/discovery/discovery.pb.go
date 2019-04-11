// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/devtools/containeranalysis/v1beta1/discovery/discovery.proto

package discovery // import "google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/discovery"

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import timestamp "github.com/golang/protobuf/ptypes/timestamp"
import common "google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/common"
import status "google.golang.org/genproto/googleapis/rpc/status"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// Whether the resource is continuously analyzed.
type Discovered_ContinuousAnalysis int32

const (
	// Unknown.
	Discovered_CONTINUOUS_ANALYSIS_UNSPECIFIED Discovered_ContinuousAnalysis = 0
	// The resource is continuously analyzed.
	Discovered_ACTIVE Discovered_ContinuousAnalysis = 1
	// The resource is ignored for continuous analysis.
	Discovered_INACTIVE Discovered_ContinuousAnalysis = 2
)

var Discovered_ContinuousAnalysis_name = map[int32]string{
	0: "CONTINUOUS_ANALYSIS_UNSPECIFIED",
	1: "ACTIVE",
	2: "INACTIVE",
}
var Discovered_ContinuousAnalysis_value = map[string]int32{
	"CONTINUOUS_ANALYSIS_UNSPECIFIED": 0,
	"ACTIVE":                          1,
	"INACTIVE":                        2,
}

func (x Discovered_ContinuousAnalysis) String() string {
	return proto.EnumName(Discovered_ContinuousAnalysis_name, int32(x))
}
func (Discovered_ContinuousAnalysis) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_discovery_0953645f1955a3d3, []int{2, 0}
}

// Analysis status for a resource. Currently for initial analysis only (not
// updated in continuous analysis).
type Discovered_AnalysisStatus int32

const (
	// Unknown.
	Discovered_ANALYSIS_STATUS_UNSPECIFIED Discovered_AnalysisStatus = 0
	// Resource is known but no action has been taken yet.
	Discovered_PENDING Discovered_AnalysisStatus = 1
	// Resource is being analyzed.
	Discovered_SCANNING Discovered_AnalysisStatus = 2
	// Analysis has finished successfully.
	Discovered_FINISHED_SUCCESS Discovered_AnalysisStatus = 3
	// Analysis has finished unsuccessfully, the analysis itself is in a bad
	// state.
	Discovered_FINISHED_FAILED Discovered_AnalysisStatus = 4
	// The resource is known not to be supported
	Discovered_FINISHED_UNSUPPORTED Discovered_AnalysisStatus = 5
)

var Discovered_AnalysisStatus_name = map[int32]string{
	0: "ANALYSIS_STATUS_UNSPECIFIED",
	1: "PENDING",
	2: "SCANNING",
	3: "FINISHED_SUCCESS",
	4: "FINISHED_FAILED",
	5: "FINISHED_UNSUPPORTED",
}
var Discovered_AnalysisStatus_value = map[string]int32{
	"ANALYSIS_STATUS_UNSPECIFIED": 0,
	"PENDING":                     1,
	"SCANNING":                    2,
	"FINISHED_SUCCESS":            3,
	"FINISHED_FAILED":             4,
	"FINISHED_UNSUPPORTED":        5,
}

func (x Discovered_AnalysisStatus) String() string {
	return proto.EnumName(Discovered_AnalysisStatus_name, int32(x))
}
func (Discovered_AnalysisStatus) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_discovery_0953645f1955a3d3, []int{2, 1}
}

// A note that indicates a type of analysis a provider would perform. This note
// exists in a provider's project. A `Discovery` occurrence is created in a
// consumer's project at the start of analysis.
type Discovery struct {
	// The kind of analysis that is handled by this discovery.
	AnalysisKind         common.NoteKind `protobuf:"varint,1,opt,name=analysis_kind,json=analysisKind,proto3,enum=grafeas.v1beta1.NoteKind" json:"analysis_kind,omitempty"`
	XXX_NoUnkeyedLiteral struct{}        `json:"-"`
	XXX_unrecognized     []byte          `json:"-"`
	XXX_sizecache        int32           `json:"-"`
}

func (m *Discovery) Reset()         { *m = Discovery{} }
func (m *Discovery) String() string { return proto.CompactTextString(m) }
func (*Discovery) ProtoMessage()    {}
func (*Discovery) Descriptor() ([]byte, []int) {
	return fileDescriptor_discovery_0953645f1955a3d3, []int{0}
}
func (m *Discovery) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Discovery.Unmarshal(m, b)
}
func (m *Discovery) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Discovery.Marshal(b, m, deterministic)
}
func (dst *Discovery) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Discovery.Merge(dst, src)
}
func (m *Discovery) XXX_Size() int {
	return xxx_messageInfo_Discovery.Size(m)
}
func (m *Discovery) XXX_DiscardUnknown() {
	xxx_messageInfo_Discovery.DiscardUnknown(m)
}

var xxx_messageInfo_Discovery proto.InternalMessageInfo

func (m *Discovery) GetAnalysisKind() common.NoteKind {
	if m != nil {
		return m.AnalysisKind
	}
	return common.NoteKind_NOTE_KIND_UNSPECIFIED
}

// Details of a discovery occurrence.
type Details struct {
	// Analysis status for the discovered resource.
	Discovered           *Discovered `protobuf:"bytes,1,opt,name=discovered,proto3" json:"discovered,omitempty"`
	XXX_NoUnkeyedLiteral struct{}    `json:"-"`
	XXX_unrecognized     []byte      `json:"-"`
	XXX_sizecache        int32       `json:"-"`
}

func (m *Details) Reset()         { *m = Details{} }
func (m *Details) String() string { return proto.CompactTextString(m) }
func (*Details) ProtoMessage()    {}
func (*Details) Descriptor() ([]byte, []int) {
	return fileDescriptor_discovery_0953645f1955a3d3, []int{1}
}
func (m *Details) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Details.Unmarshal(m, b)
}
func (m *Details) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Details.Marshal(b, m, deterministic)
}
func (dst *Details) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Details.Merge(dst, src)
}
func (m *Details) XXX_Size() int {
	return xxx_messageInfo_Details.Size(m)
}
func (m *Details) XXX_DiscardUnknown() {
	xxx_messageInfo_Details.DiscardUnknown(m)
}

var xxx_messageInfo_Details proto.InternalMessageInfo

func (m *Details) GetDiscovered() *Discovered {
	if m != nil {
		return m.Discovered
	}
	return nil
}

// Provides information about the analysis status of a discovered resource.
type Discovered struct {
	// Whether the resource is continuously analyzed.
	ContinuousAnalysis Discovered_ContinuousAnalysis `protobuf:"varint,1,opt,name=continuous_analysis,json=continuousAnalysis,proto3,enum=grafeas.v1beta1.discovery.Discovered_ContinuousAnalysis" json:"continuous_analysis,omitempty"`
	// The last time continuous analysis was done for this resource.
	LastAnalysisTime *timestamp.Timestamp `protobuf:"bytes,2,opt,name=last_analysis_time,json=lastAnalysisTime,proto3" json:"last_analysis_time,omitempty"`
	// The status of discovery for the resource.
	AnalysisStatus Discovered_AnalysisStatus `protobuf:"varint,3,opt,name=analysis_status,json=analysisStatus,proto3,enum=grafeas.v1beta1.discovery.Discovered_AnalysisStatus" json:"analysis_status,omitempty"`
	// When an error is encountered this will contain a LocalizedMessage under
	// details to show to the user. The LocalizedMessage is output only and
	// populated by the API.
	AnalysisStatusError  *status.Status `protobuf:"bytes,4,opt,name=analysis_status_error,json=analysisStatusError,proto3" json:"analysis_status_error,omitempty"`
	XXX_NoUnkeyedLiteral struct{}       `json:"-"`
	XXX_unrecognized     []byte         `json:"-"`
	XXX_sizecache        int32          `json:"-"`
}

func (m *Discovered) Reset()         { *m = Discovered{} }
func (m *Discovered) String() string { return proto.CompactTextString(m) }
func (*Discovered) ProtoMessage()    {}
func (*Discovered) Descriptor() ([]byte, []int) {
	return fileDescriptor_discovery_0953645f1955a3d3, []int{2}
}
func (m *Discovered) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Discovered.Unmarshal(m, b)
}
func (m *Discovered) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Discovered.Marshal(b, m, deterministic)
}
func (dst *Discovered) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Discovered.Merge(dst, src)
}
func (m *Discovered) XXX_Size() int {
	return xxx_messageInfo_Discovered.Size(m)
}
func (m *Discovered) XXX_DiscardUnknown() {
	xxx_messageInfo_Discovered.DiscardUnknown(m)
}

var xxx_messageInfo_Discovered proto.InternalMessageInfo

func (m *Discovered) GetContinuousAnalysis() Discovered_ContinuousAnalysis {
	if m != nil {
		return m.ContinuousAnalysis
	}
	return Discovered_CONTINUOUS_ANALYSIS_UNSPECIFIED
}

func (m *Discovered) GetLastAnalysisTime() *timestamp.Timestamp {
	if m != nil {
		return m.LastAnalysisTime
	}
	return nil
}

func (m *Discovered) GetAnalysisStatus() Discovered_AnalysisStatus {
	if m != nil {
		return m.AnalysisStatus
	}
	return Discovered_ANALYSIS_STATUS_UNSPECIFIED
}

func (m *Discovered) GetAnalysisStatusError() *status.Status {
	if m != nil {
		return m.AnalysisStatusError
	}
	return nil
}

func init() {
	proto.RegisterType((*Discovery)(nil), "grafeas.v1beta1.discovery.Discovery")
	proto.RegisterType((*Details)(nil), "grafeas.v1beta1.discovery.Details")
	proto.RegisterType((*Discovered)(nil), "grafeas.v1beta1.discovery.Discovered")
	proto.RegisterEnum("grafeas.v1beta1.discovery.Discovered_ContinuousAnalysis", Discovered_ContinuousAnalysis_name, Discovered_ContinuousAnalysis_value)
	proto.RegisterEnum("grafeas.v1beta1.discovery.Discovered_AnalysisStatus", Discovered_AnalysisStatus_name, Discovered_AnalysisStatus_value)
}

func init() {
	proto.RegisterFile("google/devtools/containeranalysis/v1beta1/discovery/discovery.proto", fileDescriptor_discovery_0953645f1955a3d3)
}

var fileDescriptor_discovery_0953645f1955a3d3 = []byte{
	// 541 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x94, 0xdf, 0x6a, 0xdb, 0x4c,
	0x10, 0xc5, 0x3f, 0x39, 0xf9, 0x92, 0x76, 0x92, 0x3a, 0x62, 0x9d, 0x52, 0xc7, 0x2d, 0xb8, 0xb8,
	0x14, 0x7a, 0xb5, 0x22, 0x69, 0x2f, 0x0a, 0xa5, 0x05, 0x55, 0x92, 0x13, 0x91, 0xb0, 0x16, 0x5a,
	0xa9, 0xd0, 0xd2, 0x22, 0xd6, 0xf2, 0x46, 0x88, 0xca, 0x5a, 0xa3, 0x95, 0x0d, 0xb9, 0xef, 0x0b,
	0xf4, 0x15, 0xfa, 0x46, 0x7d, 0xa3, 0xa2, 0xbf, 0xa9, 0x1d, 0x02, 0xee, 0x95, 0x77, 0x66, 0xcf,
	0xfc, 0xe6, 0xec, 0x31, 0x08, 0x8c, 0x48, 0x88, 0x28, 0xe1, 0xda, 0x8c, 0xaf, 0x72, 0x21, 0x12,
	0xa9, 0x85, 0x22, 0xcd, 0x59, 0x9c, 0xf2, 0x8c, 0xa5, 0x2c, 0xb9, 0x91, 0xb1, 0xd4, 0x56, 0xa7,
	0x53, 0x9e, 0xb3, 0x53, 0x6d, 0x16, 0xcb, 0x50, 0xac, 0x78, 0x76, 0x73, 0x7b, 0xc2, 0x8b, 0x4c,
	0xe4, 0x02, 0x9d, 0x44, 0x19, 0xbb, 0xe6, 0x4c, 0xe2, 0x5a, 0x8a, 0x5b, 0xc1, 0xe0, 0xfd, 0xf6,
	0xfc, 0x50, 0xcc, 0xe7, 0x22, 0xad, 0x7f, 0x2a, 0xf2, 0x60, 0x58, 0x8f, 0x97, 0xd5, 0x74, 0x79,
	0xad, 0xe5, 0xf1, 0x9c, 0xcb, 0x9c, 0xcd, 0x17, 0xb5, 0xe0, 0x49, 0x2d, 0xc8, 0x16, 0xa1, 0x26,
	0x73, 0x96, 0x2f, 0x65, 0x75, 0x31, 0xba, 0x84, 0x87, 0x66, 0xe3, 0x02, 0x7d, 0x80, 0x47, 0xcd,
	0xba, 0xe0, 0x7b, 0x9c, 0xce, 0xfa, 0xca, 0x73, 0xe5, 0x55, 0xf7, 0xec, 0x04, 0x6f, 0x1a, 0x27,
	0x22, 0xe7, 0x97, 0x71, 0x3a, 0x73, 0x0f, 0x1b, 0x7d, 0x51, 0x8d, 0x1c, 0xd8, 0x37, 0x79, 0xce,
	0xe2, 0x44, 0x22, 0x0b, 0xa0, 0x79, 0x1d, 0xaf, 0x38, 0x07, 0x67, 0x2f, 0xf1, 0xbd, 0x01, 0x60,
	0xb3, 0x15, 0xbb, 0x7f, 0x0d, 0x8e, 0x7e, 0xef, 0x02, 0xdc, 0x5e, 0xa1, 0x18, 0x7a, 0x45, 0x30,
	0x71, 0xba, 0x14, 0x4b, 0x19, 0x34, 0xbb, 0x6b, 0x9b, 0x6f, 0xb7, 0xc2, 0x63, 0xa3, 0x05, 0xe8,
	0xf5, 0xbc, 0x8b, 0xc2, 0x3b, 0x3d, 0x74, 0x01, 0x28, 0x61, 0x32, 0x6f, 0x97, 0x04, 0x45, 0xa4,
	0xfd, 0x4e, 0xf9, 0x90, 0x01, 0xae, 0xe2, 0xc4, 0x4d, 0xde, 0xd8, 0x6b, 0xf2, 0x76, 0xd5, 0x62,
	0xaa, 0xa1, 0x14, 0x6d, 0xf4, 0x0d, 0x8e, 0x5a, 0x48, 0x95, 0x7d, 0x7f, 0xa7, 0x34, 0xfc, 0x66,
	0x3b, 0xc3, 0x0d, 0x8c, 0x96, 0xb3, 0x6e, 0x97, 0xad, 0xd5, 0x68, 0x0c, 0x8f, 0x37, 0xf0, 0x01,
	0xcf, 0x32, 0x91, 0xf5, 0x77, 0x4b, 0xaf, 0xa8, 0xf1, 0x9a, 0x2d, 0x42, 0x5c, 0x23, 0x7a, 0xeb,
	0x08, 0xab, 0x90, 0x8f, 0x28, 0xa0, 0xbb, 0xd1, 0xa0, 0x17, 0x30, 0x34, 0x26, 0xc4, 0xb3, 0x89,
	0x3f, 0xf1, 0x69, 0xa0, 0x13, 0xfd, 0xea, 0x33, 0xb5, 0x69, 0xe0, 0x13, 0xea, 0x58, 0x86, 0x3d,
	0xb6, 0x2d, 0x53, 0xfd, 0x0f, 0x01, 0xec, 0xe9, 0x86, 0x67, 0x7f, 0xb2, 0x54, 0x05, 0x1d, 0xc2,
	0x03, 0x9b, 0xd4, 0x55, 0x67, 0xf4, 0x53, 0x81, 0xee, 0xba, 0x7f, 0x34, 0x84, 0xa7, 0x2d, 0x86,
	0x7a, 0xba, 0xe7, 0x6f, 0xd2, 0x0e, 0x60, 0xdf, 0xb1, 0x88, 0x69, 0x93, 0xf3, 0x0a, 0x47, 0x0d,
	0x9d, 0x90, 0xa2, 0xea, 0xa0, 0x63, 0x50, 0xc7, 0x36, 0xb1, 0xe9, 0x85, 0x65, 0x06, 0xd4, 0x37,
	0x0c, 0x8b, 0x52, 0x75, 0x07, 0xf5, 0xe0, 0xa8, 0xed, 0x8e, 0x75, 0xfb, 0xca, 0x32, 0xd5, 0x5d,
	0xd4, 0x87, 0xe3, 0xb6, 0xe9, 0x13, 0xea, 0x3b, 0xce, 0xc4, 0xf5, 0x2c, 0x53, 0xfd, 0xff, 0xe3,
	0x0f, 0x05, 0x9e, 0xc5, 0xe2, 0xfe, 0xec, 0x1d, 0xe5, 0xcb, 0xd7, 0x3a, 0xb3, 0x48, 0x24, 0x2c,
	0x8d, 0xb0, 0xc8, 0x22, 0x2d, 0xe2, 0x69, 0xf9, 0x6f, 0x6b, 0xd5, 0x15, 0x5b, 0xc4, 0xf2, 0x9f,
	0xbe, 0x06, 0xef, 0xda, 0xd3, 0xaf, 0xce, 0xce, 0xb9, 0xab, 0x4f, 0xf7, 0x4a, 0xdc, 0xeb, 0x3f,
	0x01, 0x00, 0x00, 0xff, 0xff, 0xaf, 0x60, 0x55, 0x7f, 0x5b, 0x04, 0x00, 0x00,
}
