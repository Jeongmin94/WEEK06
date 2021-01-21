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
	"SW JUNGLE WEEK06 ",
	/* First member's full name */
	"kim ",
	/* First member's email address */
	"kim9099i@hanmail.net ",
	/* Second member's full name (leave blank if none) */
	"",
	/* Second member's email address (leave blank if none) */
	""
};
/* Private global variables */
// mem_heap과 mem_brk 사이의 바이트들은 할당괸 가상메모리를 나타냄
// mem_brk 다음에 오는 바이트들은 미할당 상태
// static char* mem_heap;          // 힙의 첫 번째 바이트 포인터
// static char* mem_brk;           // 힙의 마지막 바이트 +1 포인터
// static char* mem_max_addr;      // 힙이 가질 수 있는 최대 주소 +1

// 기본 상수 및 매크로
#define WSIZE sizeof(void*)            // 워드와 헤더, 푸터의 사이즈
#define DSIZE (2*WSIZE)                // 더블 워드 사이즈
#define CHUNKSIZE (1<<12)        	   // 초기 최대 힙 사이즈

#define MAX(x, y) ((x) > (y) ? (x) : (y))

// 블록의 사이즈와 할당 여부 반환
#define PACK(size, alloc) ((size) | (alloc))

// 주소 p에 대한 읽기/쓰기
// p는 보통 void 포인터이기 때문에 사이즈를 나타내기 위해
// unsigned int 포인터로 형변환을 시켜주고 값을 가리킴
#define GET(p) (*(unsigned int *)(p))
#define PUT(p, val) (*(unsigned int*)(p) = (val))

// 블록의 사이즈와 할당 정보 가져오기
#define GET_SIZE(p)   (GET(p) & ~0x7)
#define GET_ALLOC(p)  (GET(p) & 0x1)

// 블록 포인터 bp로 헤더와 푸터의 주소를 계산한다
#define HDRP(bp)    ((char*)(bp) - WSIZE)                               // 현재 블록 헤더
#define FTRP(bp)    ((char*)(bp) + GET_SIZE(HDRP(bp))-DSIZE)            // 다음 블록 헤더

// 블록 포인터 bp로 이전 블록과 다음 블록의 주소를 계산한다.
#define NEXT_BLKP(bp) ((char*)(bp) + GET_SIZE(((char*)(bp)-WSIZE)))     // 다음 블록 bp로 이동
#define PREV_BLKP(bp) ((char*)(bp) - GET_SIZE(((char*)(bp)-DSIZE)))     // 이전 블록 bp로 이동

/* freeList의 이전 포인터와 다음 포인터 계산 */
#define NEXT_FLP(bp) (*((char **)(bp) + WSIZE)) // 다음 free list의 bp를 가져옴
#define PREV_FLP(bp) (*((char **)(bp)))			// 다음 free list의 bp를 가져옴

static void *extend_heap(size_t words);
static void place(void *bp, size_t asize);
static void *coalesce(void *bp);
static void *find_fit(size_t asize);
static void *next_fit(size_t asize);
static void *heap_listp = 0;
static void *last_bp = 0;

/*
 * mm_init - initialize the malloc package.
 * 힙 영역에 할당을 시작하는 것처럼 필수적인 시작 퍼포먼스를 실행
 * mm_init의 return value는 프로그램 시작에 문제가 생겼을 경우 -1
 * 그렇지 않을 경우 0(정상작동)
 */
int mm_init(void) {
	// 비어있는 힙 생성
	if ((heap_listp = mem_sbrk(4 * WSIZE)) == (void*)-1) return -1;
	PUT(heap_listp, 0);
	PUT(heap_listp + (1 * WSIZE), PACK(DSIZE, 1));
	PUT(heap_listp + (2 * WSIZE), PACK(DSIZE, 1));
	PUT(heap_listp + (3 * WSIZE), PACK(0, 1));
	heap_listp += (2 * WSIZE);
	last_bp = heap_listp;
	if (extend_heap(CHUNKSIZE / WSIZE) == NULL) return -1;
	return 0;
}

/*
 * mm_malloc - Allocate a block by incrementing the brk pointer.
 *     Always allocate a block whose size is a multiple of the alignment.
 * malloc은 리턴하는 메모리를 초기화하지 않는다.
 */
void* mm_malloc(size_t size)
{
	size_t adjust_size;           // 블록 사이즈 조정
	size_t extend_size;           // 힙 확장 사이즈
	char* bp;

	if (size == 0) return NULL;

	if (size <= DSIZE) adjust_size = DSIZE * 2;
	else adjust_size = DSIZE * ((size + (DSIZE)+(DSIZE - 1)) / DSIZE);

	// 사이즈에 맞는 위치 탐색
	bp = next_fit(adjust_size);
	if (bp != NULL) {
		place(bp, adjust_size);
		return bp;
	}
	// 사이즈에 맞는 위치가 없는 경우, 추가적으로 힙 영역 요청 및 배치
	extend_size = MAX(adjust_size, CHUNKSIZE);
	if ((bp = extend_heap(extend_size / WSIZE)) == NULL) return NULL;
	place(bp, adjust_size);
	// last_bp = bp;
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
 * 이전에 할당된 블록의 크기를 변경
 * bp == null => equivalent mm_malloc(size)
 * size == 0 => equivalent mm_free(bp)
 * bp != null => bp NULL이 아니면 반드시 전에 mm_malloc이나 mm_realloc으로
 *                호출된 상황
 *                이 때 mm_realloc이 실행되면 포인터가 가리키고 있던 이전 블록의 사이즈를
 *                새로운 블록의 사이즈와 주소로 리턴해주어야 한다.(교체)
 * 새로운 블록의 주소는 사용자의 설계나, 이전 블록으로 인한 내부 파편화, realloc의 사이즈에 따라 변한다.
 */
void* mm_realloc(void* bp, size_t size)
{
	if (size == 0) {
		mm_free(bp);
		return NULL;
	}
	size_t cur_size = GET_SIZE(HDRP(bp))-2*WSIZE;
	void* new_bp;
	size_t copy_len;           

	if(size < cur_size)	copy_len = size;
	else copy_len = cur_size;

	new_bp = mm_malloc(size);
	memcpy(new_bp, bp, copy_len);
	mm_free(bp);

	return new_bp;
}

static void* extend_heap(size_t words) {
	char* bp;
	size_t size;

	size = (words % 2) ? (words + 1) * WSIZE : words * WSIZE;
	if ((long)(bp = mem_sbrk(size)) == -1) return NULL;

	PUT(HDRP(bp), PACK(size, 0));
	PUT(FTRP(bp), PACK(size, 0));
	PUT(HDRP(NEXT_BLKP(bp)), PACK(0, 1));
	
	return coalesce(bp);
}

// 할당 해제시 남는 공간이 있으면 합치기
static void *coalesce(void *bp)
{
	size_t prev_alloc = GET_ALLOC(FTRP(PREV_BLKP(bp)));
	size_t next_alloc = GET_ALLOC(HDRP(NEXT_BLKP(bp)));
	size_t cur_size = GET_SIZE(HDRP(bp));
	if (prev_alloc && next_alloc) return bp;
    
	if (prev_alloc && !next_alloc) {         // 다음 블록 합치기
		cur_size += GET_SIZE(HDRP(NEXT_BLKP(bp)));
		PUT(HDRP(bp), PACK(cur_size, 0));
		PUT(FTRP(bp), PACK(cur_size, 0));
	}
	else if (!prev_alloc && next_alloc) {    // 이전 블록 합치기
		cur_size += GET_SIZE(FTRP(PREV_BLKP(bp)));
		PUT(FTRP(bp), PACK(cur_size, 0));
		PUT(HDRP(PREV_BLKP(bp)), PACK(cur_size, 0));
		bp = PREV_BLKP(bp);
	}
	else {  // 둘다 합치기
		cur_size = cur_size + GET_SIZE(HDRP(NEXT_BLKP(bp)))
			+ GET_SIZE(HDRP(PREV_BLKP(bp)));
		PUT(HDRP(PREV_BLKP(bp)), PACK(cur_size, 0));
		PUT(FTRP(NEXT_BLKP(bp)), PACK(cur_size, 0));
		bp = PREV_BLKP(bp);
	}

	// if((last_bp >=(char*)bp) && (last_bp < NEXT_BLKP(bp))) last_bp = bp;
	last_bp = bp;
	return bp;
}

// First-Fit
static void *find_fit(size_t asize)
{
	void* bp;
    bp = heap_listp;

    size_t next_alloc = GET_ALLOC(HDRP(bp));
    size_t next_size = GET_SIZE(HDRP(bp));

    while(next_size > 0) {
        if(!next_alloc && next_size >= asize) return bp;
        bp = NEXT_BLKP(bp);
        next_alloc = GET_ALLOC(HDRP(bp));
        next_size = GET_SIZE(HDRP(bp));
    }
    return NULL;
}

// Next-Fit
// last-bp
static void *next_fit(size_t asize) {
	char *bp = last_bp;

	for(last_bp; GET_SIZE(HDRP(last_bp))>0; last_bp=NEXT_BLKP(last_bp)) {
		if(!GET_ALLOC(HDRP(last_bp)) && (asize <= GET_SIZE(HDRP(last_bp)))) {
			return last_bp;
		}
	}
	for(last_bp = heap_listp; last_bp <= bp; last_bp=NEXT_BLKP(last_bp)) {
		if(!GET_ALLOC(HDRP(last_bp)) && (asize <= GET_SIZE(HDRP(last_bp)))) {
			return last_bp;
		}
	}
	return NULL;
}

// place block
static void place(void* bp, size_t asize) {
	size_t cur_size = GET_SIZE(HDRP(bp));

	if((cur_size-asize) >= 2*DSIZE) {
		PUT(HDRP(bp), PACK(asize, 1));
		PUT(FTRP(bp), PACK(asize, 1));
		bp = NEXT_BLKP(bp);
		PUT(HDRP(bp), PACK(cur_size - asize, 0));
		PUT(FTRP(bp), PACK(cur_size - asize, 0));
	}
	else {
		PUT(HDRP(bp), PACK(cur_size, 1));
		PUT(FTRP(bp), PACK(cur_size, 1));
	}
	// if(last_bp == (char*)bp) last_bp = NEXT_BLKP(bp);
}
