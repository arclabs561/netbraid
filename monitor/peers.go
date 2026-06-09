package monitor

import (
	"context"
	"crypto/rand"
	"fmt"
	"sort"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/rs/zerolog/log"
	"github.com/sourcegraph/conc/pool"
)

type peers struct {
	memberlist        *memberlist.Memberlist
	token             []byte
	cancelHealthcheck func()
}

func startNewCluster(ctx context.Context, addr string) (*peers, error) {
	token := randToken()
	mlist, err := newMemberlist(func(config *memberlist.Config) {
		config.SecretKey = token
		config.Keyring, _ = memberlist.NewKeyring(nil, config.SecretKey)
	})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	peers := &peers{
		memberlist:        mlist,
		token:             token,
		cancelHealthcheck: cancel,
	}
	p := pool.New().WithContext(ctx)
	p.Go(func(ctx context.Context) error {
		return peers.healthcheck(ctx)
	})
	return peers, nil
}

func (p *peers) Stop() {
	p.cancelHealthcheck()
}

func joinExistingCluster(
	ctx context.Context,
	addr string,
	token []byte,
) (*peers, error) {
	mlist, err := newMemberlist(func(config *memberlist.Config) {
		config.SecretKey = token
		config.Keyring, _ = memberlist.NewKeyring(nil, config.SecretKey)

	})
	if err != nil {
		return nil, err
	}
	n, err := mlist.Join([]string{addr})
	if err != nil {
		log.Fatal().Msgf("failed to join the cluster: %v", err)
	}
	log.Debug().Msgf("successfully contacted %d hosts", n)
	ctx, cancel := context.WithCancel(ctx)
	peers := &peers{
		memberlist:        mlist,
		token:             token,
		cancelHealthcheck: cancel,
	}
	p := pool.New().WithContext(ctx)
	p.Go(func(ctx context.Context) error {
		return peers.healthcheck(ctx)
	})
	return peers, nil
}

func randToken() []byte {
	key := make([]byte, 16)
	_, err := rand.Read(key)
	if err != nil {
		log.Fatal().Msgf("Failed to generate secret key: %v", err)
	}
	return key
}

func newMemberlist(fn func(config *memberlist.Config)) (*memberlist.Memberlist, error) {
	config := memberlist.DefaultWANConfig()
	config.BindPort = 7946
	config.ProbeTimeout = 4 * time.Second
	mlist, err := memberlist.Create(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create memberlist: %w", err)
	}
	return mlist, nil
}

func (peers *peers) healthcheck(ctx context.Context) error {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			members := peers.memberlist.Members()
			var addrs []string
			for _, member := range members {
				addrs = append(addrs, member.Addr.String())
			}
			sort.Strings(addrs)
			log.Debug().Str("addrs", fmt.Sprint(addrs)).
				Msgf("found %d members in the cluster", len(members))
		}
	}
}
