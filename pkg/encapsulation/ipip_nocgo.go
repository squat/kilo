// Copyright 2021 the Kilo authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !cgo
// +build !cgo

package encapsulation

// If we can determine the protocol name at runtime
// by looking it up in the protocols database, assume `ipencap`
// as this is the value in Kilo's container image.
func ipipProtocolName() string {
	return "ipencap"
}
