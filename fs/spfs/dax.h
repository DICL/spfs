#ifndef __DAX_H__
#define __DAX_H__

#define iterate_iovec(i, n, __v, __p, skip, STEP) {		\
	size_t left;						\
	size_t wanted = n;					\
	__p = i->iov;						\
	__v.iov_len = min(n, __p->iov_len - skip);		\
	if (likely(__v.iov_len)) {				\
		__v.iov_base = __p->iov_base + skip;		\
		left = (STEP);					\
		__v.iov_len -= left;				\
		skip += __v.iov_len;				\
		n -= __v.iov_len;				\
	} else {						\
		left = 0;					\
	}							\
	while (unlikely(!left && n)) {				\
		__p++;						\
		__v.iov_len = min(n, __p->iov_len);		\
		if (unlikely(!__v.iov_len))			\
			continue;				\
		__v.iov_base = __p->iov_base;			\
		left = (STEP);					\
		__v.iov_len -= left;				\
		skip = __v.iov_len;				\
		n -= __v.iov_len;				\
	}							\
	n = wanted - n;						\
}

#define iterate_and_advance(i, n, STEP) {			\
	if (unlikely(i->count < n))				\
		n = i->count;					\
	if (i->count) {						\
		size_t skip = i->iov_offset;			\
		const struct iovec *iov;			\
		struct iovec v;					\
		iterate_iovec(i, n, v, iov, skip, (STEP))	\
		if (skip == iov->iov_len) {			\
			iov++;					\
			skip = 0;				\
		}						\
		i->nr_segs -= iov - i->iov;			\
		i->iov = iov;					\
		i->count -= n;					\
		i->iov_offset = skip;				\
	}							\
}



#endif
