package queue

import (
	"container/ring"
	"errors"
	"sync"
)

type FixQueue struct {
	Ring *ring.Ring
	Mux  sync.Mutex
}

func NewFixQueue(length int) *FixQueue {
	return &FixQueue{
		Ring: ring.New(length),
	}
}

func (fq *FixQueue) Append(item interface{}) {
	fq.Mux.Lock()
	defer fq.Mux.Unlock()

	fq.Ring.Value = item
	fq.Ring = fq.Ring.Next()
}

func (fq *FixQueue) Len() (len int) {
	fq.Mux.Lock()
	defer fq.Mux.Unlock()

	len = fq.Ring.Len()
	return
}

func (fq *FixQueue) Get(idx int) (s interface{}) {
	return fq.Ring.Move(idx).Value
}

func (fq *FixQueue) ToSlice() (s []interface{}) {
	fq.Mux.Lock()
	defer fq.Mux.Unlock()

	for i := 0; i < fq.Ring.Len(); i++ {
		if fq.Ring.Value != nil {
			s = append(s, fq.Ring.Value)
		}
		fq.Ring = fq.Ring.Next()
	}
	return
}

func (fq *FixQueue) Every(item interface{}) (r bool) {
	fq.Mux.Lock()
	defer fq.Mux.Unlock()

	r = true
	for i := 0; i < fq.Ring.Len(); i++ {
		if fq.Ring.Value != item {
			r = false
		}
		fq.Ring = fq.Ring.Next()
	}

	return
}

func (fq *FixQueue) Sum() (s float64, err error) {
	fq.Mux.Lock()
	defer fq.Mux.Unlock()

	_, ok := fq.Ring.Value.(float64)
	if !ok {
		err = errors.New("Only support float64 for sum")
		return
	}

	for i := 0; i < fq.Ring.Len(); i++ {
		s += fq.Ring.Value.(float64)
		fq.Ring = fq.Ring.Next()
	}

	return
}
