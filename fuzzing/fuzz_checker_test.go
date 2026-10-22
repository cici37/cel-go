// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fuzzing

import (
	"testing"

	"cel.dev/cel-go/cel"
	"google.golang.org/protobuf/proto"

	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

func FuzzChecker(f *testing.F) {
	f.Add([]byte{})
	if env, err := getCELFuzzEnv(); err == nil {
		if ast, issues := env.Parse("1 + 2 == 3 && 'abc'.startsWith('a')"); issues.Err() == nil {
			if pe, err := cel.AstToParsedExpr(ast); err == nil {
				if b, err := proto.Marshal(pe); err == nil {
					f.Add(b)
				}
			}
		}
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		var p exprpb.ParsedExpr
		err := proto.UnmarshalOptions{
			AllowPartial:   true,
			DiscardUnknown: true,
		}.Unmarshal(in, &p)
		if err != nil {
			return
		}
		env, err := getCELFuzzEnv()
		if err != nil {
			panic(err)
		}
		_, _ = env.Check(cel.ParsedExprToAst(&p))
	})
}
