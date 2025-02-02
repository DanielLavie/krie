// Code generated by easyjson for marshaling/unmarshaling. DO NOT EDIT.

package events

import (
	json "encoding/json"
	easyjson "github.com/mailru/easyjson"
	jlexer "github.com/mailru/easyjson/jlexer"
	jwriter "github.com/mailru/easyjson/jwriter"
)

// suppress unused package warning
var (
	_ *json.RawMessage
	_ *jlexer.Lexer
	_ *jwriter.Writer
	_ easyjson.Marshaler
)

func easyjsonB0b00500DecodeGithubComGui774umeKriePkgKrieEvents(in *jlexer.Lexer, out *HookedSyscallEventSerializer) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	out.HookedSyscallEvent = new(HookedSyscallEvent)
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "syscall":
			if in.IsNull() {
				in.Skip()
				out.Syscall = nil
			} else {
				if out.Syscall == nil {
					out.Syscall = new(Syscall)
				}
				*out.Syscall = Syscall(in.Int())
			}
		case "ia_32_syscall":
			if in.IsNull() {
				in.Skip()
				out.IA32Syscall = nil
			} else {
				if out.IA32Syscall == nil {
					out.IA32Syscall = new(IA32Syscall)
				}
				*out.IA32Syscall = IA32Syscall(in.Int())
			}
		case "syscall_table":
			out.SyscallTable = SyscallTable(in.Uint32())
		case "initial_handler":
			easyjsonB0b00500DecodeGithubComGui774umeKriePkgKrieEvents1(in, &out.InitialHandler)
		case "new_handler":
			easyjsonB0b00500DecodeGithubComGui774umeKriePkgKrieEvents1(in, &out.NewHandler)
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjsonB0b00500EncodeGithubComGui774umeKriePkgKrieEvents(out *jwriter.Writer, in HookedSyscallEventSerializer) {
	out.RawByte('{')
	first := true
	_ = first
	if in.Syscall != nil {
		const prefix string = ",\"syscall\":"
		first = false
		out.RawString(prefix[1:])
		out.RawText((*in.Syscall).MarshalText())
	}
	if in.IA32Syscall != nil {
		const prefix string = ",\"ia_32_syscall\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.RawText((*in.IA32Syscall).MarshalText())
	}
	{
		const prefix string = ",\"syscall_table\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Raw((in.SyscallTable).MarshalJSON())
	}
	{
		const prefix string = ",\"initial_handler\":"
		out.RawString(prefix)
		easyjsonB0b00500EncodeGithubComGui774umeKriePkgKrieEvents1(out, in.InitialHandler)
	}
	{
		const prefix string = ",\"new_handler\":"
		out.RawString(prefix)
		easyjsonB0b00500EncodeGithubComGui774umeKriePkgKrieEvents1(out, in.NewHandler)
	}
	out.RawByte('}')
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v HookedSyscallEventSerializer) MarshalEasyJSON(w *jwriter.Writer) {
	easyjsonB0b00500EncodeGithubComGui774umeKriePkgKrieEvents(w, v)
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *HookedSyscallEventSerializer) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjsonB0b00500DecodeGithubComGui774umeKriePkgKrieEvents(l, v)
}
func easyjsonB0b00500DecodeGithubComGui774umeKriePkgKrieEvents1(in *jlexer.Lexer, out *KernelSymbol) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "address":
			out.Address = MemoryPointer(in.Uint64())
		case "symbol":
			out.Symbol = string(in.String())
		case "module":
			out.Module = string(in.String())
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjsonB0b00500EncodeGithubComGui774umeKriePkgKrieEvents1(out *jwriter.Writer, in KernelSymbol) {
	out.RawByte('{')
	first := true
	_ = first
	if in.Address != 0 {
		const prefix string = ",\"address\":"
		first = false
		out.RawString(prefix[1:])
		out.Raw((in.Address).MarshalJSON())
	}
	if in.Symbol != "" {
		const prefix string = ",\"symbol\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.Symbol))
	}
	if in.Module != "" {
		const prefix string = ",\"module\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.Module))
	}
	out.RawByte('}')
}
