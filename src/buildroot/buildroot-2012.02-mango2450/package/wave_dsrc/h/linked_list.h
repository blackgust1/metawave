
#define MAX_NUM_LIST		1024
#define NODE_DATA_SIZE		1024

#define	TRUE	1
#define	FALSE	0


typedef struct list_node
{
   struct list_node * next;       /* pointer to next node */
   struct list_node * prev;       /* pointer to next node */
   U1				data[NODE_DATA_SIZE];	
} LIST_NODE, * PLIST_NODE;

typedef struct list_header
{
   LIST_NODE * nodeMem;         /* pointer to node memory allocated */
   LIST_NODE * freeList;        /* pointer to node on free list */
   LIST_NODE * first;           /* pointer to first node of list */
   LIST_NODE * last;            /* pointer to last node of list */
   int  counter;           		/* count number of elements in list */
} LINKED_LIST, * PLINKED_LIST;


/********************** list toolkit functions ********************/

LINKED_LIST * listCreate(LINKED_LIST *pHeader, LIST_NODE *pNodeMem, int nNodes);

LIST_NODE * listInsert( LINKED_LIST * pList, U1 *buf, LIST_NODE * pWhere);

unsigned long listDelete( LINKED_LIST * pList, LIST_NODE * pNode );

LIST_NODE   * listFind( LINKED_LIST * pList, unsigned long tid );


/********************** list toolkit macros **********************/

/*******************************************************************
*        listFirst(pList) --  returns a pointer to the first node  *
*            of the list or NULL if list is empty                  *
*                                                                  *
*       pre-conditions:  "pList" is already initialized            *
*                                                                  *
*       post-conditions: none                                      *
*******************************************************************/
#define listFirst(pList)    ((pList == NULL) ? NULL : (pList)->first)


/*******************************************************************
*       listLast(pList) --  returns a pointer to the last node     *
*            of the list or NULL if list is empty                  *
*                                                                  *
*       pre-conditions:  "pList" is already initialized            *
*                                                                  *
*       post-conditions: none                                      *
*******************************************************************/
#define listLast(pList)     ((pList == NULL) ? NULL : (pList)->last)


/*******************************************************************
*       listNext(pNode) --  returns a pointer to the next node     *
*            following the given node or NULL if node is NULL      *
*                                                                  *
*       preconditions: list has been initialized                   *
*                      "pNode" is a pointer to a List_Node or NULL * 
*                                                                  *
*       postconditions: none                                       *
*******************************************************************/
#define listNext(pNode)              ((pNode == NULL) ? NULL : ((pNode)->next))




