package argon2phc_test

import (
	"context"
	"fmt"
	"log"

	"github.com/jacob2161/argon2phc"
)

func Example() {
	hasher, err := argon2phc.NewHasher(nil)
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	encoded, err := hasher.Hash(ctx, "correct horse battery staple")
	if err != nil {
		log.Fatal(err)
	}
	matched, err := hasher.Matches(ctx, encoded, "correct horse battery staple")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(matched, hasher.NeedsRehash(encoded))
	// Output: true false
}
