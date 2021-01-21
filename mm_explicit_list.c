
//(영후) 안녕하세요 ^_^


/*
 * mm-naive.c - The fastest, least memory-efficient malloc package.
 *
 * In this naive approach, a block is allocated by simply incrementing
 * the brk pointer.  A block is pure payload. There are no headers or
 * footers.  Blocks are never coalesced or reused. Realloc is
 * implemented directly using mm_malloc and mm_free.
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include "mm.h"
#include "memlib.h"

 /*********************************************************
  * NOTE TO STUDENTS: Before you do anything else, please
  * provide your team information in the following struct.
  ********************************************************/
team_t team = {
	/* Team name */
	"WEEK06",
	/* First member's full name */
	"Jeongmin",
	/* First member's email address */
	"kim9099i@hanmail.net",
	/* Second member's full name (leave blank if none) */
	"",
	/* Second member's email address (leave blank if none) */
	""
};

#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~0x7)			// (영후) 이 매크로는 사용되지 않았네요!    										<---------
#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))						// (영후) 이 매크로는 implicit 이든 explicit이든 사용할 일이 없었더라구요.			 <---------

// MACROS
#define WSIZE 4
#define DSIZE 8
#define CHUNKSIZE 1<<12

#define MAX(x, y) ((x) > (y) ? (x) : (y))
#define PACK(size, alloc) ((size) | (alloc))

#define GET(p) (*(unsigned int *)(p))
#define PUT(p, val) (*(unsigned int *)(p) = (val))

#define GET_SIZE(p) (GET(p) & ~0x7)
#define GET_ALLOC(p) (GET(p) & 0x1)

#define HDRP(bp) ((char *)(bp)-WSIZE)
#define FTRP(bp) ((char *)(bp) + GET_SIZE(HDRP(bp)) - DSIZE)

#define NEXT_BLK(bp) ((char *)(bp) + GET_SIZE(HDRP(bp)))
#define PREV_BLK(bp) ((char *)(bp)-GET_SIZE(HDRP(bp) - WSIZE))

#define NEXT_PTR(bp) (*(char **)(bp + WSIZE))
#define PREV_PTR(bp) (*(char **)(bp))

static char *heap_listp = 0;
static char *free_list = 0;

static void *extend_heap(size_t words);
static void place(void *bp, size_t asize);
static void *find_fit(size_t asize);
static void *coalesce(void *bp);
static void del_free(void* bp);

/*
 * mm_init - initialize the malloc package.
 */
int mm_init(void)
{
	heap_listp = mem_sbrk(4 * DSIZE);							// (영후) 매크로에 MINIMUM = 24 는 따로 설정 해주지 않으셨지만
	if (heap_listp == (void*)-1) return -1;						//		초기 init 블록이 32byte 크기를 갖고있는 것으로 보아 해당 방식으로 진행하려고 하신 듯 하군요!

	PUT(heap_listp, 0);										// padding
	PUT(heap_listp + WSIZE, PACK(3* DSIZE, 1));				// header
	PUT(heap_listp + 2 * WSIZE, 0);							// prev
	PUT(heap_listp + 3 * WSIZE, 0);							// next					
	PUT(heap_listp + 6 * WSIZE, PACK(3 * DSIZE, 1));		// footer
	PUT(heap_listp + 7 * WSIZE, PACK(0, 1));				// epilogue

	free_list = heap_listp + DSIZE;
	if (extend_heap(CHUNKSIZE / WSIZE) == NULL) return -1;
	return 0;
}

/*
 * mm_malloc - Allocate a block by incrementing the brk pointer.
 *     Always allocate a block whose size is a multiple of the alignment.
 */
void* mm_malloc(size_t size)
{
	size_t asize;
	size_t extendsize;
	char* bp;

	if (size == 0) return NULL;

	if (size <= DSIZE) asize = 2 * DSIZE;
	else asize = DSIZE * ((size + (DSIZE)+(DSIZE - 1)) / DSIZE);

    bp = find_fit(asize);
	if (bp != NULL) {
		place(bp, asize);
		return bp;
	}

	extendsize = MAX(asize, CHUNKSIZE);
    bp = extend_heap(extendsize/WSIZE);	
	if (bp == NULL) return NULL;									// (영후) 보통 extend_heap 가드를 bp 초기화(윗줄)와 함께 한 줄로 진행하던데, 나눠 놓으시니 이것도 보기가 좋네요
	place(bp, asize);
	return bp;
}

/*
 * mm_free - Freeing a block does nothing.
 */
void mm_free(void* bp)
{
	size_t size = GET_SIZE(HDRP(bp));
	PUT(HDRP(bp), PACK(size, 0));
	PUT(FTRP(bp), PACK(size, 0));
	coalesce(bp);
}

/*
 * mm_realloc - Implemented simply in terms of mm_malloc and mm_free
 */
void* mm_realloc(void* bp, size_t size)									// (영후) realloc을 직접 구현하셨네요!
{																		
	if (size == 0) {
		mm_free(bp);
		return NULL;
	}
	size_t cur_size = GET_SIZE(HDRP(bp))-2*WSIZE;
	void* new_bp;
	size_t copy_len;           
																		// (영후) 잠시 메모 좀 하겠습니다.
	if(size < cur_size)	copy_len = size;								// (영후) 현 블록의 사이즈가 재할당하려는 사이즈보다 큰 경우 copy_len = 재할당 사이즈
	else copy_len = cur_size;											// (영후) 현 블록의 사이즈가 재할당하려는 사이즈보다 작은 경우 copy_len = 현 블록의 사이즈

	new_bp = mm_malloc(size);											// (영후) 일단 재할당 size만큼 말록을 진행하기
	memcpy(new_bp, bp, copy_len);										// (영후) 말록된 곳에 현 블록 컨텐츠를 copy_len 만큼 진행하기
	mm_free(bp);														// (영후) 현 블록 free

	return new_bp;														// (영후) 기본 realloc 과 크게 다른 점은 없어보이는데 기본 realloc은 호환이 안 되는게 신기하네요! 
}																		//		제가 놓친게 있다면 알려주시면 감사하겠습니다! (혹시 위에 size==0 인 경우의 코드 때문일까요?) 

// 힙 확장
static void *extend_heap(size_t words)
{
	char* bp;
	size_t size;

	size = (words % 2) ? (words + 1) * DSIZE : words * DSIZE;
	bp = mem_sbrk(size);
	if((long)(bp == -1)) return NULL;

	PUT(HDRP(bp), PACK(size, 0));
	PUT(FTRP(bp), PACK(size, 0));
	PUT(HDRP(NEXT_BLK(bp)), PACK(0, 1));
	return coalesce(bp);
}

// 힙 병합
static void* coalesce(void* bp) {
	size_t prev_alloc = GET_ALLOC(FTRP(PREV_BLK(bp)));
	size_t next_alloc = GET_ALLOC(HDRP(NEXT_BLK(bp)));
	size_t size = GET_SIZE(HDRP(bp));

	// 다음 블록 병합
	if (prev_alloc && !next_alloc) {
		size += GET_SIZE(HDRP(NEXT_BLK(bp)));
		del_free(NEXT_BLK(bp));										// (영후) del_free 함수를 따로 만드셔서 코드가 말끔하네요! 저는 그냥 함수를 따로 안 만들고 다 써보려했다가 터져버렸어요 ^_^
		PUT(HDRP(bp), PACK(size, 0));
		PUT(FTRP(bp), PACK(size, 0));
	}
	// 이전 블록 병합
	else if (!prev_alloc && next_alloc) {
		size += GET_SIZE(FTRP(PREV_BLK(bp)));
		bp = PREV_BLK(bp);
		del_free(bp);
		PUT(HDRP(bp), PACK(size, 0));
		PUT(FTRP(bp), PACK(size, 0));
	}
	// 이전 다음 블록 병합
	else if (!prev_alloc && !next_alloc) {
		size += (GET_SIZE(FTRP(PREV_BLK(bp))) + GET_SIZE(HDRP(NEXT_BLK(bp))));
		del_free(PREV_BLK(bp));
		del_free(NEXT_BLK(bp));
		bp = PREV_BLK(bp);
		PUT(HDRP(bp), PACK(size, 0));
		PUT(FTRP(bp), PACK(size, 0));
	}
	NEXT_PTR(bp) = free_list;
	PREV_PTR(free_list) = bp;
	PREV_PTR(bp) = NULL;
	free_list = bp;
	return bp;
}

static void del_free(void* bp) {
	if (PREV_PTR(bp) != NULL) {
		NEXT_PTR(PREV_PTR(bp)) = NEXT_PTR(bp);
	}
	else {
		free_list = NEXT_PTR(bp);
	}
	PREV_PTR(NEXT_PTR(bp)) =  PREV_PTR(bp);
    // bp = NEXT_PTR(bp);
}

static void* find_fit(size_t asize) {								// (영후)  next_fit으로 돌아가는 모습도 보고싶어요!!!!
	void* bp;
	for (bp = free_list; GET_ALLOC(HDRP(bp)) == 0; bp = NEXT_PTR(bp)) {
		if (GET_SIZE(HDRP(bp)) >= asize) {
            return (char*)bp;
        }
	}
	return NULL;
}

// find test
static void* find_fit2(size_t asize) {					
	void* bp;
    int cnt =0;
    void* high = mem_heap_hi();
    printf("mem_brk : %p\n", high);
	for (bp = free_list; bp != NULL; bp = NEXT_PTR(bp)) {
		// if (GET_SIZE(HDRP(bp)) >= asize) {
        //     printf("find fit addr %p\n", bp);
        //     return (char*)bp;
        // }
        cnt++;
        printf("cnt : %d\n", cnt);
	}
	return NULL;
}

static void place(void* bp, size_t asize) {
	size_t size = GET_SIZE(HDRP(bp));

    del_free(bp);
	if (size - asize >= 2 * DSIZE) {
		PUT(HDRP(bp), PACK(asize, 1));
		PUT(FTRP(bp), PACK(asize, 1));
		bp = NEXT_BLK(bp);
		PUT(HDRP(bp), PACK(size - asize, 0));
		PUT(FTRP(bp), PACK(size - asize, 0));
		coalesce(bp);
	}
	else {
		PUT(HDRP(bp), PACK(size, 1));
		PUT(FTRP(bp), PACK(size, 1));
	}
}


// (영후) 전반적으로 코드가 말끔해 보여서 보기 좋았습니다. explicit 으로 84점!! 수고 많으셨습니다 ^_^