package merkle

// func TestFrontier(t *testing.T) {
// 	cases := []struct {
// 		inp  []string
// 		want maptier
// 	}{
// 		// xxx {},
// 		{
// 			inp: []string{"a"},
// 			want: maptier{
// 				'a': newMaptier(),
// 			},
// 		},
// 		{
// 			inp: []string{"a", "b"},
// 			want: maptier{
// 				'a': newMaptier(),
// 				'b': newMaptier(),
// 			},
// 		},
// 		{
// 			inp: []string{"a", "ab"},
// 			want: maptier{
// 				'a': maptier{
// 					'b': newMaptier(),
// 				},
// 			},
// 		},
// 		{
// 			inp: []string{"ab"},
// 			want: maptier{
// 				'a': maptier{
// 					'b': newMaptier(),
// 				},
// 			},
// 		},
// 	}

// 	for i, c := range cases {
// 		t.Run(fmt.Sprintf("case %d", i+1), func(t *testing.T) {
// 			var f Frontier
// 			for _, s := range c.inp {
// 				f.Exclude([]byte(s))
// 			}
// 			if !f.top.equal(c.want) {
// 				t.Errorf("got:\n%s\nwant:\n%s", spew.Sdump(f.top), spew.Sdump(c.want))
// 			}
// 		})
// 	}
// }
