package vlan

import (
	"reflect"
	"testing"
)

func TestInit(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{
			name:    "1",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := Init(); (err != nil) != tt.wantErr {
				t.Errorf("Init() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_initNIF(t *testing.T) {
	type args struct {
		systemNIFs     []*NetworkInterface
		dbBusinessNIFs []*NetworkInterface
		manageNIFName  string
	}
	tests := []struct {
		name    string
		args    args
		want    []*NetworkInterface
		want1   []string
		wantErr bool
	}{
		{
			args: args{
				systemNIFs:     []*NetworkInterface{{Name: "1"}, {Name: "2"}, {Name: "3"}},
				dbBusinessNIFs: []*NetworkInterface{{Name: "2"}, {Name: "3"}},
				manageNIFName:  "1",
			},
			want:    []*NetworkInterface{{Name: "2"}, {Name: "3"}},
			want1:   []string{},
			wantErr: false,
		},
		{
			args: args{
				systemNIFs:     []*NetworkInterface{{Name: "1"}, {Name: "2"}, {Name: "3"}, {Name: "4"}},
				dbBusinessNIFs: []*NetworkInterface{{Name: "2"}, {Name: "3"}},
				manageNIFName:  "1",
			},
			want:    []*NetworkInterface{{Name: "2"}, {Name: "3"}, {Name: "4"}},
			want1:   []string{},
			wantErr: false,
		},
		{
			args: args{
				systemNIFs:     []*NetworkInterface{{Name: "1"}, {Name: "2"}, {Name: "3"}, {Name: "4"}},
				dbBusinessNIFs: []*NetworkInterface{{Name: "3"}},
				manageNIFName:  "1",
			},
			want:    []*NetworkInterface{{Name: "2"}, {Name: "3"}, {Name: "4"}},
			want1:   []string{},
			wantErr: false,
		},
		{
			args: args{
				systemNIFs:     []*NetworkInterface{{Name: "1"}, {Name: "2"}, {Name: "3"}, {Name: "4"}},
				dbBusinessNIFs: []*NetworkInterface{{Name: "3"}, {Name: "5"}},
				manageNIFName:  "1",
			},
			want:    []*NetworkInterface{{Name: "2"}, {Name: "3"}, {Name: "4"}},
			want1:   []string{"5"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := initNIF(tt.args.systemNIFs, tt.args.dbBusinessNIFs, tt.args.manageNIFName)
			if (err != nil) != tt.wantErr {
				t.Errorf("initNIF() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("initNIF() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("initNIF() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func Test_getMaskNumberMax(t *testing.T) {
	type args struct {
		ips []m
	}
	tests := []struct {
		name    string
		args    args
		want    *m
		wantErr bool
	}{
		{
			name: "1",
			args: args{
				ips: []m{
					{
						name:       "1",
						ipCIDR:     "192.168.1.11/24",
						groupIndex: 0,
					},
					{
						name:       "1",
						ipCIDR:     "192.168.1.222/25",
						groupIndex: 1,
					},
				},
			},
			want: &m{
				name:       "1",
				ipCIDR:     "192.168.1.222/25",
				groupIndex: 1,
			},
			wantErr: false,
		},
		{
			name: "2",
			args: args{
				ips: []m{
					{
						name:       "1",
						ipCIDR:     "192.168.1.11/24",
						groupIndex: 0,
					},
					{
						name:       "1",
						ipCIDR:     "192.168.1.222/16",
						groupIndex: 1,
					},
				},
			},
			want: &m{
				name:       "1",
				ipCIDR:     "192.168.1.11/24",
				groupIndex: 0,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getMaskNumberMax(tt.args.ips)
			if (err != nil) != tt.wantErr {
				t.Errorf("getMaskNumberMax() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getMaskNumberMax() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getAppIPCidr(t *testing.T) {
	type args struct {
		appIP  string
		ipCidr string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "1",
			args: args{
				appIP:  "192.168.1.11",
				ipCidr: "192.168.1.12/24",
			},
			want:    "192.168.1.11/24",
			wantErr: false,
		},
		{
			name: "2",
			args: args{
				appIP:  "192.168.1.11",
				ipCidr: "192.168.2.12/24",
			},
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getAppIPCidr(tt.args.appIP, tt.args.ipCidr)
			if (err != nil) != tt.wantErr {
				t.Errorf("getAppIPCidr() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getAppIPCidr() got = %v, want %v", got, tt.want)
			}
		})
	}
}
