
/* GENERAL OVERVIEW
 * ----------------
 *
 * This driver performs compression/decompression of data for XIO. It is
 * designed with ease of further development in mind - modifying the driver
 * to support different methods of compressing data does not require a deep
 * understanding of most of the code.
 *
 * The drivers consists of two separate sets of functions: those that
 * handle various aspects of the communication with XIO (hereafter refered to
 * as the block functionality), and those that handle the actual data (this 
 * would be all functions that has the word "handle" in it's name).
 * 
 * These are entirely separate entities; the block functionality does not know
 * and does not care what the data handling functions does with the data, as
 * long as they fulfill certain requirements. These requirements are outlined
 * in the comments related to each function.
 *
 * This separation means that a lot of this code can also be re-used to perform
 * entirely different tasks (for example checksums at the block-level)
 *
 * FLOW OF EXECUTION
 * -----------------
 *
 * globus_l_xio_compression_activate();
 * globus_l_xio_compression_init();
 * globus_l_xio_compression_open();
 *
 * If driver is on write-side and while there is more data:
 *
 *     globus_l_xio_compression_write();
 *         globus_l_xio_compression_handle_write();
 *             globus_l_xio_compression_set_strategy():
 *             (strategy-specific function)
 *     globus_l_xio_compression_write_cb();
 *
 * If driver is on read-side and while there is more data:
 *
 *     If there is data in the waiting_buffer:
 *         globus_l_xio_compression_read();
 *     Else:
 *         globus_l_xio_compression_read();
 *         globus_l_xio_compression_read_block_header_cb();
 *         globus_l_xio_compression_read_body_cb();
 *             globus_l_xio_compression_handle_buffer_size();
 *             globus_l_xio_compression_handle_read();
 *                 (strategy-specific function)
 *
 * globus_l_xio_compression_close();
 * globus_l_xio_compression_destroy();
 * globus_l_xio_compression_deactivate();
 *
 *
 * HOW TO ADD COMPRESSION STRATEGIES
 * ---------------------------------
 *
 * 1. #include necessary .h files
 * 2. Add a new value to the enum xio_l_compression_strategies_s
 * 3. If necessary, add initializations to globus_l_xio_compression_init()
 * 4. Create a function that compresses data using your strategy, and one that
 *    decompresses
 * 5. Add a case to the switch statements in the handle_write() and 
 *    handle_read()
 *    functions that uses your newly created functions to compress and
 *    decompress the source buffer into the destination buffer
 *
 * That's it! You don't need to concern yourself with adding any header
 * information, or how the rest of the code deals with the data. See existing
 * strategies for examples.
 *
 * 
 * HOW TO REUSE THE BLOCK-FUNCTIONALITY TO CREATE AN ENTIRELY DIFFERENT DRIVER
 * ---------------------------------------------------------------------------
 *
 * TODO
 *
 * 
 * PACKET MAKEUP
 * -------------
 *
 * Each packet has 2 headers and 1 body in the following format:
 * 
 * ===============
 * Block Header
 * ---------------
 * Buffer Header
 * ---------------
 * Body
 * ===============
 *
 * The block header is the domain of the block-handling functions, with one
 * caveat:
 * While the handle() functions does not have direct access to the block-
 * header, it's fields are set based on the iov_len-member of the arguements
 * header_dest and payload_dest to globus_l_xio_compression_handle_write().
 * 
 * The buffer header is entirely the domain of the various handle()-functions.
 * The block handling functions does not make any assumptions about it's
 * contents. Therefore, any and all changes can be made to this header within
 * the handle() functions without changing the block-handling code.
 *
 * Block header:
 * -------------------
 * Offset  | Length | Description
 * ----------------------
 * 0       | 1      | Buffer header length (max 255)
 * 1       | 4      | Body length as a network byte ordered 32 bit int
 *                    (this is the compressed length of the payload)
 * 
 *
 * Buffer Header:
 * ---------------------
 * Offset  | Length | Description
 * ---------------------
 * 0       | 1      | Compression strategy
 * 1       | 4      | Uncompressed length as a 32 bit int in network byte order
 *
 */


#include "globus_xio_driver.h"
#include "globus_xio_load.h"
#include "globus_common.h"
#include "globus_xio_compression_driver.h"
#include "version.h"
// esjung
#if 1
#include "blosc.h"


static 	globus_mutex_t 	blosc_mutex;
#endif

/* ZZZ zlib ZZZ*/

#if defined(HAVE_LIBZ)
#    include <zlib.h>
#endif

#undef HAVE_LIBLZO

#if defined(HAVE_LIBLZO)
#    include <lzo/lzo1x.h>
#    include <lzo/lzodefs.h>
#    include <lzo/lzoconf.h>
#    include <lzo/lzoutil.h>
#endif

#define HEADER_LEN (1 + sizeof(uint32_t))
#define BLOCK_HEADER_LEN (1 + sizeof(uint32_t))

GlobusDebugDefine(GLOBUS_XIO_COMPRESSION);
GlobusXIODeclareDriver(compression);

#define _DEBUG_
/* dbug is used for debug printouts. Turned on/off by #define DBUG */
#if 1 // esjung

#ifdef _DEBUG_
#   define dbug(x, args...)  \
do \
{\
    printf(x, ##args);\
} while(0)
#else
#   define dbug(x, args...)  
#endif

#else

#   define dbug(x, args...)  \
do \
{\
    char * _msg; \
    _msg = globus_common_create_string(x, ##args);\
    GlobusDebugPrintf(GLOBUS_XIO_COMPRESSION, GLOBUS_XIO_COMPRESSION_DEBUG_INFO, (_msg)); \
    globus_free(_msg); \
} while(0)

#endif

#define XIOCompressMsg(m) \

#define GlobusXIOCompressionDebugdbug(level, message)                  \
    GlobusDebugPrintf(GLOBUS_XIO_COMPRESSION, level, message)

#define GlobusXIOCompressionDebugEnter()                               \
    GlobusXIOCompressionDebugdbug(                                     \
        GLOBUS_XIO_COMPRESSION_DEBUG_TRACE,                            \
        ("[%s] Entering\n", _xio_name))

#define GlobusXIOCompressionDebugExit()                                \
    GlobusXIOCompressionDebugdbug(                                     \
        GLOBUS_XIO_COMPRESSION_DEBUG_TRACE,                            \
        ("[%s] Exiting\n", _xio_name))

/* macros for error handling */
#define GlobusXIOCompressionError(_reason)                             \
    globus_error_put(GlobusXIOCompressionErrorObject(_reason))

#define GlobusXIOCompressionErrorObject(_reason)                  \
    globus_error_construct_error(                                      \
        GLOBUS_XIO_MODULE,                                             \
        GLOBUS_NULL,                                                   \
        1,                                                             \
        __FILE__,                                                      \
        _xio_name,                                                     \
        __LINE__,                                                      \
        _XIOSL(_reason))                                               \

#if 1 //esjung: add thr_id field
typedef struct xio_l_compression_driver_handle_s xio_l_compression_driver_handle_t;// due to not being able to forward reference.
typedef struct xio_l_compression_req_s xio_l_compression_req_t;// due to not being able to forward reference.
typedef struct globus_l_xio_compression_bounce_s 
{
    xio_l_compression_driver_handle_t *	driver_handle;
    globus_xio_operation_t              op;
    globus_xio_iovec_t *                iovec;
    int									iovec_count; 
    globus_xio_iovec_t *                new_iovec;
    int									new_iovec_count; 
	globus_size_t						wait_for;
	xio_l_compression_req_t *			req;
    int									thr_id;  
} globus_l_xio_compression_bounce_t;
#else
typedef struct globus_l_xio_compression_bounce_s
{
    void *                              driver_specific_handle;
    globus_xio_operation_t              op;
    globus_xio_iovec_t *                iovec;
    int                                 iovec_count; 
} globus_l_xio_compression_bounce_t;
#endif

typedef enum
{
    GLOBUS_XIO_COMPRESSION_DEBUG_ERROR = 1,
    GLOBUS_XIO_COMPRESSION_DEBUG_WARNING = 2,
    GLOBUS_XIO_COMPRESSION_DEBUG_TRACE = 4,
    GLOBUS_XIO_COMPRESSION_DEBUG_INFO = 8,
} globus_xio_compression_debug_levels_t;

typedef enum xio_l_compression_strategies_s
{
    DEFAULT_COMPRESSION = 0,
    NO_COMPRESSION_MEMCPY = 1,
    NO_COMPRESSION_POINTERS = 2,
    ZLIB_DEFAULT_COMPRESSION = 3,
    LZO_DEFAULT_COMPRESSION = 4,
} xio_l_compression_strategies_t;

#if 1 // esjung: add thread pool info
typedef struct xio_l_compression_worker_thr_s
{
    globus_size_t		nr_thread;
    globus_thread_t		*pthreads;
    globus_l_xio_compression_bounce_t *pbounces;
    globus_mutex_t		common_mutex;
	globus_cond_t		wait_cond;
	globus_cond_t		ready_cond;
	globus_cond_t		finish_cond;
    globus_size_t		nr_wait_worker;
	globus_size_t		nr_ready_worker;
    globus_size_t		nr_finish_worker;
	uint16_t			exit_flag;
	
} xio_l_compression_worker_thr_t;

struct xio_l_compression_driver_handle_s
{
    xio_l_compression_worker_thr_t	worker_thr;
    
    globus_xio_iovec_t        waiting_buffer;
    globus_size_t			waiting_buffer_bookmark;
    globus_xio_iovec_t *    original_iovec;
    globus_size_t			original_iovec_count;            
};
#else
typedef struct xio_l_compression_driver_handle_s
{
    globus_xio_iovec_t        waiting_buffer;
    globus_size_t             waiting_buffer_bookmark;
    globus_xio_iovec_t *    original_iovec;
} xio_l_compression_driver_handle_t;
#endif

struct xio_l_compression_req_s
{
    /* TODO: this struct should be cleaned up - lots of unused members*/
    globus_size_t                       original_size;
    globus_xio_iovec_t *                user_buffer;
    globus_xio_iovec_t *                waiting_buffer;
    globus_byte_t                       header_len;
    globus_byte_t                       block_header[BLOCK_HEADER_LEN];
    globus_xio_iovec_t *                iov_to_free;
    globus_xio_iovec_t *                buffers_to_free;
    globus_xio_iovec_t                  iovec[2];
    xio_l_compression_driver_handle_t * compression_handle;
    globus_size_t			wait_for;
};

/* Function declarations */

static int
globus_l_xio_compression_activate();

static int
globus_l_xio_compression_deactivate();

static 
globus_result_t
globus_l_xio_compression_init(globus_xio_driver_t * out_driver);

static void
globus_l_xio_compression_destroy(globus_xio_driver_t driver);

static
globus_result_t
globus_l_xio_compression_open(
    const globus_xio_contact_t *        contact_info,
    void *                              driver_link,
    void *                              driver_attr,
    globus_xio_operation_t              op);

static
void
globus_l_xio_compression_open_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg);

static
globus_result_t
globus_l_xio_compression_close(
    void *                              driver_specific_handle,
    void *                              attr,
    globus_xio_operation_t              op);

static
globus_result_t
globus_l_xio_compression_read(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op);

static
void
globus_l_xio_compression_read_block_header_cb(
    struct globus_i_xio_op_s *          op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg);

static
void
globus_l_xio_compression_read_body_cb(
    struct globus_i_xio_op_s *          op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg);

static
globus_xio_iovec_t *
globus_l_xio_compression_handle_buffer_size(
    const globus_xio_iovec_t *          header_source,
    const globus_xio_iovec_t *          payload_source,
    globus_xio_iovec_t *                user_buffer,
    globus_xio_iovec_t *                waiting_buffer);

static
globus_result_t
globus_l_xio_compression_handle_read(
    globus_xio_iovec_t *                dest,
    const globus_xio_iovec_t *          header_source,
    const globus_xio_iovec_t *          payload_source);

static
globus_result_t
globus_l_xio_compression_handle_read_no_compression(
    globus_xio_iovec_t *                dest,
    globus_xio_iovec_t *                source,
    int 				uncompressed_len,
    globus_byte_t                       flag);

static
globus_result_t
globus_l_xio_compression_handle_read_lzo(
    globus_xio_iovec_t *                dest,
    globus_xio_iovec_t *                source,
    int 				uncompressed_len);

static
globus_result_t
globus_l_xio_compression_handle_write_lzo(
    globus_xio_iovec_t *                dest,
    const globus_xio_iovec_t *          source);

static
globus_result_t
globus_l_xio_compression_write(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op);

#if 1 // esjung
static
void *
globus_l_xio_compression_mt_write(
    void *                              bounce_arg);
#endif

#if 0 // esjung: not defined
static
void
globus_l_xio_compression_write_os(
    void *                              user_arg);
#endif
    
static
globus_result_t
globus_l_xio_compression_handle_write(
    globus_xio_iovec_t *                header_dest,
    globus_xio_iovec_t *                payload_dest,
    const globus_xio_iovec_t *          source);

static
globus_result_t
globus_l_xio_compression_handle_write_no_compression(
    globus_xio_iovec_t *                dest,
    const globus_xio_iovec_t *          source,
    globus_byte_t                       flag);

static
globus_result_t
globus_l_xio_compression_handle_read_zlib(
    globus_xio_iovec_t *                dest,
    const globus_xio_iovec_t *          source,
    int 				uncompressed_len);

static
globus_result_t
globus_l_xio_compression_handle_write_zlib(
    globus_xio_iovec_t *                dest,
    const globus_xio_iovec_t *          source,
    globus_byte_t                       level);

static
void
globus_l_xio_compression_write_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg);

static
globus_byte_t
globus_l_xio_compression_set_strategy (
    globus_xio_iovec_t *                iovec);

/* Activation and deactivation code:
 * When the driver is loaded the activate() function below is called. If any
 * global initializations are needed, they should be done in this function.
 * Conversly, when the driver is unloaded or the driver exits, deactivate
 * is called. The time between activate() and deactivate() should be seen
 * as the lifetime of the driver.
 */
GlobusXIODefineModule(compression) =
{
    "globus_xio_compression",
    globus_l_xio_compression_activate,
    globus_l_xio_compression_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

static
int
globus_l_xio_compression_activate(void)
{
    int                                 rc;
    dbug("globus_l_xio_compression_activate() called\n");
    dbug("Compression driver version 0.2.0\n");

    GlobusDebugInit(GLOBUS_XIO_COMPRESSION, ERROR WARNING TRACE INFO);

#if 1 // esjung
    //dbug("ESJUNG: set thread model to GLOBUS_THREAD_MODEL_PTHREADS\n");
    //globus_thread_set_model(GLOBUS_THREAD_MODEL_PTHREADS);
    globus_mutex_init(&blosc_mutex, (globus_mutexattr_t *) GLOBUS_NULL);
#endif

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    if(rc == GLOBUS_SUCCESS)
    {
        GlobusXIORegisterDriver(compression);
    }

    return rc;
}

static
int
globus_l_xio_compression_deactivate(void)
{
    int                                	rc;

#if 1 // esjung
	globus_mutex_destroy(&blosc_mutex);
#endif
    dbug("globus_l_xio_compression_deactivate() called\n");

    GlobusXIOUnRegisterDriver(compression);
    rc = globus_module_deactivate(GLOBUS_XIO_MODULE);

    return rc;    
}

/* Initialization and deinitialization code:
 * The functions that XIO need for initialization and deinitialization
 * are supplied by the call to GlobusXIODefineDriver below.
 *
 * The init() function is called whenever the user calls 
 * globus_xio_driver_load(). This is when the user start explicitly
 * making use of the driver.
 *
 * The _init() and _destroy() functions can be called serveral times in the
 * same process space (thereby separating them from _activate and
 * _deactivate()).
 */
GlobusXIODefineDriver(
    compression,
    globus_l_xio_compression_init,
    globus_l_xio_compression_destroy);

static
globus_result_t
globus_l_xio_compression_init(
    globus_xio_driver_t *               out_driver)
{
    globus_xio_driver_t                 driver;
    globus_result_t                     globus_result;
    GlobusXIOName(globus_l_xio_compression_init);

    dbug("globus_l_xio_compression_init() called\n");

    globus_result = globus_xio_driver_init(&driver, "compression", NULL);
    if(globus_result != GLOBUS_SUCCESS)
    {
        return globus_result;
    }

    globus_xio_driver_set_transform(
        driver,
        globus_l_xio_compression_open,
        globus_l_xio_compression_close,
        globus_l_xio_compression_read,
        globus_l_xio_compression_write,
        NULL,
        NULL);

    *out_driver = driver;

#   if defined(HAVE_LIBLZO)
    {
        int                             lzo_result;
        /* Also do compression-library specific inits here */
        lzo_result = lzo_init();
        if (lzo_result != LZO_E_OK)
        {
            globus_result = GlobusXIOCompressionError("lzo_init() failed");

            return globus_result;
        }
    }
#   endif

    return GLOBUS_SUCCESS;
}

static
void
globus_l_xio_compression_destroy(
    globus_xio_driver_t                driver)
{
    dbug("globus_l_xio_compression_destroy() called\n");
    globus_xio_driver_destroy(driver);
}

/* _open() is called whenever XIO needs to open a file/TCP-connection/
 * what-have-you.
 */

static
globus_result_t
globus_l_xio_compression_open(
    const globus_xio_contact_t *       contact_info,
    void *                             driver_link,
    void *                             driver_attr,
    globus_xio_operation_t             op)
{
    globus_result_t                    res;

    dbug("globus_l_xio_compression_open() called\n");

    res = globus_xio_driver_pass_open(
        op, contact_info, globus_l_xio_compression_open_cb, NULL);

    return res;
}

/* Because we need a unique waiting_buffer for each connection, we create a
 * driver handle in this callback function, and attach an iovec to it. This
 * handle will then be threaded through as the driver_specific_handle to the
 * read and (more importantly) write functions.
 */
static
void
globus_l_xio_compression_open_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    xio_l_compression_driver_handle_t * driver_handle;

    dbug("globus_l_xio_compression_open_cb() called\n");

    driver_handle = (xio_l_compression_driver_handle_t *) 
        globus_malloc(sizeof(xio_l_compression_driver_handle_t));
    
    driver_handle->waiting_buffer.iov_len = 0;
    driver_handle->waiting_buffer_bookmark = 0;

#if 1 // esjung: create thread pools for compression
	//blosc_init();
	globus_mutex_lock(&blosc_mutex);
	blosc_set_nthreads(8);
	globus_mutex_unlock(&blosc_mutex);

    dbug("ESJUNG: create a worker thread pool.\n");
    int i, ret;

    dbug("ESJUNG: initialize worker_mutex and related variables\n");
    globus_mutex_init(&driver_handle->worker_thr.common_mutex, (globus_mutexattr_t *) GLOBUS_NULL);
    globus_cond_init(&driver_handle->worker_thr.wait_cond, (globus_condattr_t *) GLOBUS_NULL);
    globus_cond_init(&driver_handle->worker_thr.ready_cond, (globus_condattr_t *) GLOBUS_NULL);
    globus_cond_init(&driver_handle->worker_thr.finish_cond, (globus_condattr_t *) GLOBUS_NULL);
    driver_handle->worker_thr.nr_wait_worker = 0;
    driver_handle->worker_thr.nr_ready_worker = 0;
    driver_handle->worker_thr.nr_finish_worker = 0;
    driver_handle->worker_thr.exit_flag = 0;

    driver_handle->worker_thr.nr_thread = 4;
    driver_handle->worker_thr.pthreads = globus_malloc(sizeof(globus_thread_t)*driver_handle->worker_thr.nr_thread);
    driver_handle->worker_thr.pbounces = globus_malloc(sizeof(globus_l_xio_compression_bounce_t)*driver_handle->worker_thr.nr_thread);

    for (i=0; i<driver_handle->worker_thr.nr_thread; i++)
    {
        driver_handle->worker_thr.pbounces[i].driver_handle = driver_handle;
        driver_handle->worker_thr.pbounces[i].iovec = NULL;
        driver_handle->worker_thr.pbounces[i].iovec_count = 0;
        driver_handle->worker_thr.pbounces[i].new_iovec = NULL;
        driver_handle->worker_thr.pbounces[i].new_iovec_count = 0;
        driver_handle->worker_thr.pbounces[i].req = NULL;
        driver_handle->worker_thr.pbounces[i].thr_id = i;
	  ret = globus_thread_create(
	  	   &driver_handle->worker_thr.pthreads[i],
	  	   GLOBUS_NULL,
	  	   globus_l_xio_compression_mt_write,
	  	   (void *)&driver_handle->worker_thr.pbounces[i]);
	  if (ret != GLOBUS_SUCCESS) {
	      dbug("create thread error.\n");
		exit(1);
	  }
    }    	
#endif

    globus_xio_driver_finished_open(driver_handle, op, result);    
}

#if 1 // esjung: destruct allocated structures such as worker_thr.
/*
 * 1. set exit_flag
 * 2. thread_join()
 * 3. clean up allocated resources.
 */

/* In _close() we have no special needs and thus we simply pass the operation 
 * to the next driver without supplying a callback-function.
 */
static
globus_result_t
globus_l_xio_compression_close(
    void *                              driver_specific_handle,
    void *                              attr,
    globus_xio_operation_t              op)
{
	int									i,status,nr_worker;
    globus_result_t                     res;
	xio_l_compression_driver_handle_t *	driver_handle;

    dbug("globus_l_xio_compression_close() called\n");

	// 1. set exit_flag
    dbug("globus_l_xio_compression_close(): set exit_flag\n");
	driver_handle = (xio_l_compression_driver_handle_t *)driver_specific_handle;
	driver_handle->worker_thr.exit_flag = driver_handle->worker_thr.nr_thread;
	
	// 2. thread_join()
#if 1
	//blosc_destroy();

	globus_mutex_lock(&driver_handle->worker_thr.common_mutex);
	driver_handle->worker_thr.nr_ready_worker++;
	nr_worker = driver_handle->worker_thr.nr_thread;
	dbug("globus_l_xio_compression_close(): nr_ready_worker %d\n", driver_handle->worker_thr.nr_ready_worker);
	if (driver_handle->worker_thr.nr_ready_worker == (nr_worker+1))
	{
		driver_handle->worker_thr.nr_ready_worker = 0;
		dbug("%d: cond_broadcast\n"); 
		globus_cond_broadcast(&driver_handle->worker_thr.ready_cond);
	}
	else
		globus_cond_wait(&driver_handle->worker_thr.ready_cond, &driver_handle->worker_thr.common_mutex); // wait
	globus_mutex_unlock(&driver_handle->worker_thr.common_mutex);

    dbug("globus_l_xio_compression_close(): thread_join()\n");
	while (1) {
		globus_mutex_lock(&driver_handle->worker_thr.common_mutex);
		if (driver_handle->worker_thr.exit_flag == 0) {
			globus_mutex_unlock(&driver_handle->worker_thr.common_mutex);
			break;
		}
		globus_mutex_unlock(&driver_handle->worker_thr.common_mutex);
	}
#else
	for (i=0; i<driver_handle->worker_thr.nr_thread; i++)
		//globus_thread_join(driver_handle->worker_thr.pthreads[i], &status); 
		globus_thread_cancel(driver_handle->worker_thr.pthreads[i]); 
#endif

	// 3. clean up allocated resources.
    dbug("globus_l_xio_compression_close(): clean up allocated resources\n");
	// mutex, cond_var
	globus_cond_destroy(&driver_handle->worker_thr.wait_cond);	
	globus_cond_destroy(&driver_handle->worker_thr.ready_cond);	
	globus_cond_destroy(&driver_handle->worker_thr.finish_cond);	
	globus_mutex_destroy(&driver_handle->worker_thr.common_mutex);

	// free allocated memory
	globus_free(driver_handle->worker_thr.pbounces);
	globus_free(driver_handle);

    res = globus_xio_driver_pass_close(
        op, NULL, NULL);
    return res;
}
#else
/* In _close() we have no special needs and thus we simply pass the operation 
 * to the next driver without supplying a callback-function.
 */
static
globus_result_t
globus_l_xio_compression_close(
    void *                              driver_specific_handle,
    void *                              attr,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;

    dbug("globus_l_xio_compression_close() called\n");
    
    res = globus_xio_driver_pass_close(
        op, NULL, NULL);
    return res;
}
#endif

static
globus_result_t
globus_l_xio_compression_read(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
	xio_l_compression_driver_handle_t * handle;
	xio_l_compression_req_t *           req;
	globus_result_t                     result;
	globus_xio_iovec_t *                waiting_buffer;
	int                                 waiting_buffer_bookmark;
	int                                	next_waiting_buffer_bookmark;
	globus_size_t                       read_bytes;
	globus_byte_t *			l_buf;

	dbug("globus_l_xio_compression_read() called\n");

	/* First, we need to check if there's data in the waiting buffer. If so, 
 	* we simply fill the iovec with that data and call finished_read().
 	*/    
	handle = (xio_l_compression_driver_handle_t *) driver_specific_handle;
	waiting_buffer_bookmark = handle->waiting_buffer_bookmark;
	waiting_buffer = &handle->waiting_buffer;
    next_waiting_buffer_bookmark = waiting_buffer_bookmark;

    if (waiting_buffer_bookmark > 0 ) 
    {
        dbug("Data in waiting_buffer to be processed\n");
        dbug("waiting_buffer->iov_len: %d\n", waiting_buffer->iov_len);
        /* Now, there are two cases to deal with: 1) when the entire 
         * waiting_buffer fits into the iovec, and 2) when it doesn't.
         * 
         * First, we need to determine how many bytes to copy from
         * waiting_buffer to iovec. We also need to update 
         * waiting_buffer_bookmark so that subsequent calls will be handled
         * properly.
         *
         * The first case is when the entire (remaining) waiting_buffer will
         * fit into the the user iovec:
         */
        if (iovec->iov_len >= (waiting_buffer->iov_len -
            waiting_buffer_bookmark)) 
        {
            read_bytes = waiting_buffer->iov_len - waiting_buffer_bookmark;
            /* Setting next_waiting_buffer_bookmark = 0 indicates that we
             * have read the entire waiting_buffer, and that it may be free():d
             * below */
            next_waiting_buffer_bookmark = 0;
        }
        /* Case two: */
        else {
            /* We will copy as much as will fit of waiting_buffer into the
             * user iovec */
            read_bytes = iovec->iov_len;
            /* Update the bookmark so that subsequent calls will begin copying
             * from the right position */
            next_waiting_buffer_bookmark += read_bytes;
        }

        dbug("Waiting_buffer_bookmark: %d\n", waiting_buffer_bookmark);
        dbug("Read_bytes: %d\n", read_bytes);
        dbug("Iovec_iov_len: %d\n", iovec->iov_len);

        /* Then, simply memcpy read_bytes into iovec, update waiting_buffer_
         * bookmark and call finished_read. */
	l_buf = (globus_byte_t *) waiting_buffer->iov_base;
        memcpy(iovec->iov_base, &l_buf[waiting_buffer_bookmark], read_bytes);

        handle->waiting_buffer_bookmark = next_waiting_buffer_bookmark;

        globus_xio_driver_finished_read(op, GLOBUS_SUCCESS, read_bytes);

        if (next_waiting_buffer_bookmark == 0) 
        { 
            /*waiting_buffer empty, clean up.*/
            globus_free(waiting_buffer->iov_base);
            waiting_buffer->iov_base = NULL;
            waiting_buffer->iov_len = 0;
        }
        return GLOBUS_SUCCESS;
    }

    /* The req struct will be threaded through first to the
     * read_block_header_cb()-function, and then on to read_body_cb().
     * Why this is necessary (rather than just convinent) will
     * be explained below.
     */
    req = globus_calloc(1, sizeof(xio_l_compression_req_t));

    /* The iovec arguement passed to this interface function is what will 
     * finally be passed on to the user. Since we won't have any data to
     * actually fill this with until we get to read_body_cb, we need to
     * stow it away in req->user_buffer.
     */

    req->user_buffer = (globus_xio_iovec_t *) iovec;

    /* Note that when pass_read() is called below, the second arguement is 
     * req->iovec. This means that this is the buffer that XIO will fill with
     * data. Since we want to be able to actually access this data later we 
     * stow it away in req, same as above.
     * 
     * Assigning iov_base to &req->block_header is mainly a matter of 
     * convinience.
     */
    req->iovec->iov_base = &req->block_header;
    req->iovec->iov_len = BLOCK_HEADER_LEN;

    /* We also need to attach the handle */
    req->compression_handle = handle;

	dbug("BEFORE globus_xio_driver_pass_read()\n");
	result = globus_xio_driver_pass_read(
		op, req->iovec, 1, BLOCK_HEADER_LEN,
		globus_l_xio_compression_read_block_header_cb, req);
	dbug("AFTER globus_xio_driver_pass_read()\n");
    if (result != GLOBUS_SUCCESS) 
    {
        globus_free(req);
    }
    return result;
}

static
void
globus_l_xio_compression_read_block_header_cb(
    struct globus_i_xio_op_s *          op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    xio_l_compression_req_t *           req;
    uint32_t                            block_len;
    globus_byte_t                       next_header_len;
    globus_size_t			wait_for;

    dbug("globus_l_xio_compression_read_block_header_cb() called\n");

    req = (xio_l_compression_req_t *) user_arg;

    /* If the incoming result != GLOBUS_SUCCESS, we need to clean up
     * and return */
    if (result != GLOBUS_SUCCESS) 
    {
        globus_free(req);
        globus_xio_driver_finished_read(op, result, 0);
        return;
    } 
    assert(nbytes == BLOCK_HEADER_LEN);

    memcpy(&block_len, &req->block_header[1], sizeof(block_len));
    block_len = ntohl(block_len);

    next_header_len = (globus_byte_t) req->block_header[0];
    req->iovec[0].iov_base = malloc(next_header_len);
    req->iovec[0].iov_len = next_header_len;
    /* One possible performance booster would to read the data straight
     * into the user_buffer here, in those cases where the actual payload won't
     * need to be modified. 
     *  
     * This will however require some rewriting of the block-handling code.*/

    req->iovec[1].iov_base = malloc(block_len);
    req->iovec[1].iov_len = block_len;

    wait_for = block_len + next_header_len;
    dbug("reading %d into 0 and %d into 1: waiting for %d\n", next_header_len, block_len, wait_for);


    req->wait_for = wait_for;
	dbug("2 BEFORE globus_xio_driver_pass_read()\n");
	globus_xio_driver_pass_read(op, req->iovec, 2, wait_for,
		globus_l_xio_compression_read_body_cb, req);
	dbug("2 AFTER globus_xio_driver_pass_read()\n");
}

static
void
globus_l_xio_compression_read_body_cb(
    struct globus_i_xio_op_s *          op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    xio_l_compression_req_t *           req;
    globus_size_t                       final_length;    
    globus_xio_iovec_t *                waiting_buffer;
    globus_xio_iovec_t *                destination_buffer;

    dbug("globus_l_xio_compression_read_body_cb() called: %d\n", nbytes);

    req = (xio_l_compression_req_t *)   user_arg;
    
    if (result != GLOBUS_SUCCESS) 
    {
        dbug("Incoming result != GLOBUS_SUCESS\n");
        globus_free(req);
        globus_xio_driver_finished_read(op, result, 0);

        return;
    }

    globus_assert(nbytes == req->wait_for);

    waiting_buffer = &req->compression_handle->waiting_buffer;

    destination_buffer = globus_l_xio_compression_handle_buffer_size(
        &req->iovec[0], &req->iovec[1], req->user_buffer, waiting_buffer);

    result = globus_l_xio_compression_handle_read(destination_buffer, 
        &req->iovec[0], &req->iovec[1]);

	if (result != GLOBUS_SUCCESS)
	{
		dbug("globus_l_xio_compression_handle_read() error");
		final_length = 0;
		globus_xio_driver_finished_read(op, result, final_length);
		return;
 	}


    /* Final length is the number of bytes we have actually read.
     * req->user_buffer->iov_len is guaranteed to reflect this by the
     * handle_buffer_size() function called above */
    final_length = req->user_buffer->iov_len;
        
    /* If the waiting_buffer has been used to store the data, we need to copy
     * as much as we can into the user_buffer, and also set the bookmark */
    if (destination_buffer == waiting_buffer)
    {
        memcpy(req->user_buffer->iov_base, waiting_buffer->iov_base,
            final_length);
        req->compression_handle->waiting_buffer_bookmark = final_length;
    }

    /* Call finished_read to notify XIO that we have completed the
     * operation. The third arguement to finished_read() signifies the
     * number of bytes from user_buffer that will actually be passed on
     * to the user.
     */
    dbug("Final_length: %d\n", final_length);

    globus_xio_driver_finished_read(op, result, final_length);

    globus_free(req->iovec[0].iov_base);
    globus_free(req->iovec[1].iov_base);
    globus_free(req);
}

/* This function is intended to guarantee that handle_read() is given a
 * destination buffer that will fit the entire payload.
 *
 * It's tasks are:
 * 1) Determine the size required to fit the entire payload. For some drivers
 * (such as compression) this will be based on the header, for others it will
 * simply be payload_source->iov_len (for drivers that do not modify the 
 * actual data, such as a checksum-driver).
 * 2) Determine if the user_buffer is big enough. If so, set the iov_len so that
 * it matches the space actually needed and return it.
 * 3) If the user_buffer is not big enough this function shall instead allocate
 * sufficient space in the waiting_buffer, set it's iov_len  and return it.
 */
static
globus_xio_iovec_t *
globus_l_xio_compression_handle_buffer_size(
    const globus_xio_iovec_t *          header_source,
    const globus_xio_iovec_t *          payload_source,
    globus_xio_iovec_t *                user_buffer,
    globus_xio_iovec_t *                waiting_buffer)
{
    uint32_t                            uncompressed_len;
    globus_byte_t *                     hs_buf;

    dbug("globus_l_xio_compression_handle_buffer_size() called\n");

    hs_buf = header_source->iov_base;
    /* In the case of the compression driver, which buffer we use will
     * depend on the uncompressed_len field of the header */
    memcpy(&uncompressed_len, &hs_buf[1], 
        sizeof(uint32_t));
    uncompressed_len = ntohl(uncompressed_len);

    dbug("uncompressed_len: %d\n", uncompressed_len);

    /* Will the user_buffer have room for the entire decompressed buffer? */
    if (uncompressed_len <= user_buffer->iov_len)
    {
        dbug("handle_buffer_size returning user_buffer\n");    
        /* If the user_buffer is big enough, we just set the iov_len return it*/
        user_buffer->iov_len = uncompressed_len;
        return user_buffer;
    }
    else 
    {
        dbug("handle_buffer_size returning waiting_buffer\n");    
        /* The user buffer is too small, we need to malloc space in the
         * waiting_buffer and return that instead. */
        waiting_buffer->iov_base = globus_malloc(uncompressed_len);
        waiting_buffer->iov_len = uncompressed_len;
        return waiting_buffer;
    }
}



/* All the actual data handling is supposed to take place in handle_read().
 * It is expected to fill up dest based on the content of header_source and
 * payload_source.
 *
 * dest will be guaranteed to be large enough to fit the entire payload by
 * the handle_buffer_size() function above.
 */
static
globus_result_t
globus_l_xio_compression_handle_read(
    globus_xio_iovec_t *                dest,
    const globus_xio_iovec_t *          header_source,
    const globus_xio_iovec_t *          payload_source)
{
	globus_byte_t *                     header_buffer;
	globus_byte_t                       strategy;
	uint32_t                            uncompressed_len;
	globus_byte_t                       header_index = 0;
	globus_result_t                     result;
	GlobusXIOName(globus_l_xio_compression_handle_read);

	dbug("globus_l_xio_compression_handle_read() called\n");

	dbug("dest.iov_len: %d\n", dest->iov_len);
	dbug("payload_source.iov_len: %d\n", payload_source->iov_len);

    /* First, parse the elements of the header that will be the same
     * for all strategies */
    header_buffer = header_source->iov_base;

    strategy = header_buffer[header_index];
    header_index++;
    memcpy(&uncompressed_len, &header_buffer[header_index], sizeof(uint32_t));
    uncompressed_len = ntohl(uncompressed_len);
    header_index += sizeof(uint32_t);

    /* Then direct the buffers to the appropriate helper-function depending
     * on strategy */
    switch (strategy)
    {
        case NO_COMPRESSION_POINTERS :
            dbug("Strategy: NO_COMPRESSION_POINTER\n");
            result = globus_l_xio_compression_handle_read_no_compression(
                dest, (globus_xio_iovec_t *)payload_source, uncompressed_len,
                NO_COMPRESSION_POINTERS);
            break;
        case NO_COMPRESSION_MEMCPY :
            dbug("Strategy: NO_COMPRESSION_MEMCPY\n");
            result = globus_l_xio_compression_handle_read_no_compression(
                dest,  (globus_xio_iovec_t *)payload_source, uncompressed_len,
                NO_COMPRESSION_MEMCPY);
            break;
        case LZO_DEFAULT_COMPRESSION :
            dbug("Strategy: LZO_DEFAULT_COMPRESSION\n");
            result = globus_l_xio_compression_handle_read_lzo(
                dest,  (globus_xio_iovec_t *)payload_source, uncompressed_len);
            break;
        case ZLIB_DEFAULT_COMPRESSION :
            dbug("Strategy: ZLIB_DEFAULT_COMPRESSION\n");
            result = globus_l_xio_compression_handle_read_zlib(
                dest,  (globus_xio_iovec_t *)payload_source, uncompressed_len);
            break;
        default :
            result = GlobusXIOCompressionError(
                "compression strategy not recognized. Incompatible driver" 
                "at other end?");
            break;
    }

    return result;
}

static
globus_result_t
globus_l_xio_compression_handle_read_no_compression (
    globus_xio_iovec_t *                dest,
    globus_xio_iovec_t *                source,
    int 				uncompressed_len,
    globus_byte_t                       flag)
{
    dest->iov_len = source->iov_len;

    if (flag == NO_COMPRESSION_MEMCPY)
    {
        dbug("Strategy: NO_COMPRESSION_MEMCPY\n");
        memcpy(dest->iov_base, source->iov_base, dest->iov_len);
    }
    if (flag == NO_COMPRESSION_POINTERS)
    {    
        dbug("Strategy: NO_COMPRESSION_POINTERS\n");
        dest->iov_base = source->iov_base;
    }
    return GLOBUS_SUCCESS;
}


static
globus_result_t
globus_l_xio_compression_handle_read_lzo(
    globus_xio_iovec_t *                dest,
    globus_xio_iovec_t *                source,
	int 				uncompressed_len)
{
    GlobusXIOName(globus_l_xio_compression_handle_read_lzo);

#   if defined(HAVE_LIBLZO)
    {
        globus_result_t                 globus_result;
        int                            	lzo_result;

        lzo_result = lzo1x_decompress(source->iov_base, source->iov_len, 
            dest->iov_base, &dest->iov_len, NULL);

        if (lzo_result != LZO_E_OK)
        {
            globus_result = GlobusXIOCompressionError("lzo decompression failed");
            return globus_result;
        }
    }
#   else
    {
        return GlobusXIOCompressionError("No lzo");
    }
#   endif

    return GLOBUS_SUCCESS;
}

static void zlib_error_dbg(int ez)
{
	switch(ez)
	{
		case Z_OK:
		    break;
		case Z_MEM_ERROR:
		    dbug("memory error %d\n", ez);
		    break;
		case Z_BUF_ERROR:
		    dbug("buf error %d\n", ez);
		    break;
		case Z_DATA_ERROR:
		    dbug("data error%d\n", ez);
		    break;
		default:
		    dbug("some other error %d\n", ez);
	}
}

#if 1 // esjung

static
globus_result_t
globus_l_xio_compression_handle_read_zlib(
    globus_xio_iovec_t *                dest,
    const globus_xio_iovec_t *          source,
	int 				uncompressed_len)
{
	GlobusXIOName(globus_l_xio_compression_handle_read_zlib);

	dbug("globus_l_xio_compression_handle_read_blosc() called.\n");

	uLongf			compressed_len;
	uLongf			decompressed_len;
	globus_result_t	globus_result;

	assert(uncompressed_len <= dest->iov_len);

	/* Decompress */
	compressed_len = source->iov_len;
	globus_mutex_lock(&blosc_mutex);
	decompressed_len = blosc_decompress(
			(const void *) source->iov_base,
			(void *) dest->iov_base, 
			uncompressed_len);
	globus_mutex_unlock(&blosc_mutex);

	if (decompressed_len <= 0 && source->iov_len > 0)
	{
		dbug("globus_l_xio_compression_handle_read_blosc() failed\n");
		globus_result = GlobusXIOCompressionError("BLOSC decompression failed");
		return globus_result;
	}

    return GLOBUS_SUCCESS;
}

#else

static
globus_result_t
globus_l_xio_compression_handle_read_zlib(
    globus_xio_iovec_t *                dest,
    const globus_xio_iovec_t *          source,
	int 				uncompressed_len)
{
    GlobusXIOName(globus_l_xio_compression_handle_read_zlib);

	dbug("globus_l_xio_compression_handle_read_zlib() called.\n");

#   if defined(HAVE_LIBZ)
    {
        uLongf                          compressed_len;
        uLongf                          decompressed_len;
        int                            	zlib_result;
        globus_result_t                 globus_result;

	assert(uncompressed_len <= dest->iov_len);
        /* Decompress */
        compressed_len = source->iov_len;
        decompressed_len = uncompressed_len;
        zlib_result = uncompress(
            (Byte *) dest->iov_base, 
            (uLongf *) &decompressed_len,
            (Byte *) source->iov_base,
            compressed_len);

        if (zlib_result != Z_OK)
        {
	    zlib_error_dbg(zlib_result);
            dbug("globus_l_xio_compression_handle_read_zlib() failed\n");
            globus_result = GlobusXIOCompressionError(
                "zlib decompression failed");
            return globus_result;
        }
    }
#   else
    {
        return GlobusXIOCompressionError("No zlib");
    }
#   endif
    return GLOBUS_SUCCESS;
}

#endif

#if 1 
// esjung: multi-threaded per iovec write
/*
 * Steps:
 * 1. Get my_id.
 * 2. Infinitely do the following tasks.
 *    2.1 Lock worker_mutex/increase nr_wait_worker/Unlock worker_mutex
 *        If nr_wait_worker == nr_thread then cond_signal()
 *    2.2 ------barrier; waken up by _thread_kicker() or other peers
 *    2.3 Compress data region computed by my_id.
 *    2.4 Lock worker_mutex/increase nr_finish_worker/Unlock worker_mutex
 *    2.5 check exit_flag and if set, thread exit()
 */
static
void *
globus_l_xio_compression_mt_write(
    void *                              bounce_arg)
{
    globus_result_t                     result;
    xio_l_compression_req_t *           req;
    globus_xio_iovec_t *                iov;
    globus_xio_iovec_t *                iovec;
    globus_byte_t *                     block_header;
    globus_size_t                       wait_for = 0;
    int                                 i;
    int                                	j;
    uint32_t                            buffer_len;
    globus_l_xio_compression_bounce_t	*bounce;
    // esjung
    int									my_id;
	int 								nr_worker;
	xio_l_compression_driver_handle_t *	driver_handle;	
	
    GlobusXIOName(globus_l_xio_compression_mt_write);

    dbug("globus_l_xio_compression_mt_write() called\n");

    // 1. Get my_id
    bounce = (globus_l_xio_compression_bounce_t *)bounce_arg;
	driver_handle = bounce->driver_handle;
	nr_worker = driver_handle->worker_thr.nr_thread;

    my_id = bounce->thr_id;
    dbug("globus_l_xio_compression_mt_write(): my_id: %d\n", my_id);

    // 2. Infinitely looping doing the following tasks.
	while (1)
	{
    	// 2.1 Lock worker_mutex/increase nr_wait_worker/Unlock worker_mutex
    	dbug("globus_l_xio_compression_mt_write(): %d wait phase.\n", my_id);
		globus_mutex_lock(&(driver_handle->worker_thr.common_mutex));
		driver_handle->worker_thr.nr_wait_worker++;
		if (driver_handle->worker_thr.nr_wait_worker == driver_handle->worker_thr.nr_thread)
			globus_cond_signal(&driver_handle->worker_thr.wait_cond);
		globus_mutex_unlock(&(driver_handle->worker_thr.common_mutex));

		// 2.2 ------barrier; waken up by _thread_kicker() or other peers
    	dbug("globus_l_xio_compression_mt_write(): %d ready phase.\n", my_id);
		globus_mutex_lock(&driver_handle->worker_thr.common_mutex);
		driver_handle->worker_thr.nr_ready_worker++;
		dbug("%d: nr_worker %d, nr_ready_worker %d\n", my_id, nr_worker, driver_handle->worker_thr.nr_ready_worker);
		if (driver_handle->worker_thr.nr_ready_worker == (nr_worker+1))
		{
			driver_handle->worker_thr.nr_ready_worker = 0;
			dbug("%d: cond_broadcast\n", my_id); 
			globus_cond_broadcast(&driver_handle->worker_thr.ready_cond);
		}
		else
			globus_cond_wait(&driver_handle->worker_thr.ready_cond, &driver_handle->worker_thr.common_mutex); // wait
		globus_mutex_unlock(&driver_handle->worker_thr.common_mutex);

		// thread exit()
		if (driver_handle->worker_thr.exit_flag > 0) {
			dbug("%d: thread_exit()\n", my_id); 
			globus_mutex_lock(&driver_handle->worker_thr.common_mutex);
			driver_handle->worker_thr.exit_flag--;
			globus_mutex_unlock(&driver_handle->worker_thr.common_mutex);
			globus_thread_exit(GLOBUS_NULL);
		}

		// 2.3 Compress data region computed by my_id.
    	dbug("globus_l_xio_compression_mt_write(): %d execution phase.\n", my_id);

	    /* Create a new iovec to store compressed data and header in */
   		iov = bounce->new_iovec; iovec = bounce->iovec;

		/* We need req to thread malloced data through to the callback function
		* for freeing */
	    req = bounce->req;

	    for (i = 0, j = 0; i < bounce->iovec_count; i++)
		{
			if ( my_id != (i%(bounce->driver_handle->worker_thr.nr_thread)) )
				continue;
 
			result = globus_l_xio_compression_handle_write(
				&iov[i*3+1], &iov[i*3+2], &iovec[i]);

        	if (result != GLOBUS_SUCCESS)
        	{
           		//return result;
				break;
			}

			if (iov[i*3+1].iov_len > 256) 
        	{
				//result = GlobusXIOCompressionError(
            	//    "maximum header length violated by handle_write()");
            	//return result;
				break;
        	}

			/* Create the block-header */
			block_header = globus_malloc(BLOCK_HEADER_LEN);
			block_header[0] = iov[i*3+1].iov_len;
			buffer_len = htonl(iov[i*3+2].iov_len);
			memcpy(&block_header[1], &buffer_len, sizeof(buffer_len));
    
			iov[i*3].iov_base = block_header;
			iov[i*3].iov_len = BLOCK_HEADER_LEN;

			bounce->wait_for += iov[i*3].iov_len + iov[i*3+1].iov_len + iov[i*3+2].iov_len;

			/* The buffers we have malloced will need to be threaded through to
			* write_cb for freeing */
			req->buffers_to_free[j] = iov[i*3];
			j++;
			req->buffers_to_free[j] = iov[i*3+1];
        	j++;
        	/* Space may or may not have been malloced by handle_read() for the
         	* payload-destination, therefore we need this conditional assignment:
         	*/
        	if (iov[i*3+2].iov_base != iovec[i].iov_base) 
        	{
				req->buffers_to_free[j] = iov[i*3+2];
            	j++;
        	}
        	/* Finally, we need to keep track of the original size */
        	req->original_size += iovec[i].iov_len;
        	dbug("iov[%d].iov_len = %d\n", i*3, iov[i*3].iov_len);
        	dbug("iov[%d].iov_len = %d\n", i*3+1, iov[i*3+1].iov_len);
        	dbug("iov[%d].iov_len = %d\n", i*3+2, iov[i*3+2].iov_len);
    	}
    	/* We also need to free the iov itself in the callback */
    	req->iov_to_free = iov;

   		dbug("%d: wait_for %d\n", my_id, bounce->wait_for);

		// 2.4 Lock worker_mutex/increase nr_finish_worker/Unlock worker_mutex
    	dbug("globus_l_xio_compression_mt_write(): %d finish phase.\n", my_id);
		globus_mutex_lock(&(driver_handle->worker_thr.common_mutex));
		driver_handle->worker_thr.nr_finish_worker++;
		if (driver_handle->worker_thr.nr_finish_worker == driver_handle->worker_thr.nr_thread)
			globus_cond_signal(&driver_handle->worker_thr.finish_cond);
		globus_mutex_unlock(&(driver_handle->worker_thr.common_mutex));

	}

}

#endif

static
globus_result_t
globus_l_xio_compression_fake_write(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_result_t                     result;
    xio_l_compression_req_t *           req;
    globus_xio_iovec_t *                iov;
    globus_byte_t *                     block_header;
    globus_size_t                       wait_for = 0;
    int                                 i;
    int                                	j;
    uint32_t                            buffer_len;
    GlobusXIOName(globus_l_xio_compression_write);

    dbug("globus_l_xio_compression_write() called\n");

    /* Create a new iovec to store compressed data and header in */
    iov = (globus_xio_iovec_t *) globus_calloc(3 * iovec_count,
        sizeof(globus_xio_iovec_t));

    /* We need req to thread malloced data through to the callback function
     * for freeing */
    req = globus_calloc(sizeof(xio_l_compression_req_t), 1);
    /* adding 1 here so there is always a null one when we go to free */
    req->buffers_to_free = (globus_xio_iovec_t *) globus_calloc(1+3* iovec_count,
        sizeof(globus_xio_iovec_t));

    for (i = 0, j = 0; i < iovec_count; i++)
    {
        result = globus_l_xio_compression_handle_write(
            &iov[i*3+1], &iov[i*3+2], &iovec[i]);

        if (result != GLOBUS_SUCCESS)
        {
            return result;
        }

        if (iov[i*3+1].iov_len > 256) 
        {
            result = GlobusXIOCompressionError(
                "maximum header length violated by handle_write()");
            return result;
        }

        /* Create the block-header */
        block_header = globus_malloc(BLOCK_HEADER_LEN);
        block_header[0] = iov[i*3+1].iov_len;
        buffer_len = htonl(iov[i*3+2].iov_len);
        memcpy(&block_header[1], &buffer_len, sizeof(buffer_len));
    
        iov[i*3].iov_base = block_header;
        iov[i*3].iov_len = BLOCK_HEADER_LEN;

        wait_for += iov[i*3].iov_len + iov[i*3+1].iov_len + iov[i*3+2].iov_len;

        /* The buffers we have malloced will need to be threaded through to
         * write_cb for freeing */
        req->buffers_to_free[j] = iov[i*3];
        j++;
        req->buffers_to_free[j] = iov[i*3+1];
        j++;
        /* Space may or may not have been malloced by handle_read() for the
         * payload-destination, therefore we need this conditional assignment:
         */
        if (iov[i*3+2].iov_base != iovec[i].iov_base) 
        {
            req->buffers_to_free[j] = iov[i*3+2];
            j++;
        }
        /* Finally, we need to keep track of the original size */
        req->original_size += iovec[i].iov_len;
        dbug("iov[%d].iov_len = %d\n", i*3, iov[i*3].iov_len);
        dbug("iov[%d].iov_len = %d\n", i*3+1, iov[i*3+1].iov_len);
        dbug("iov[%d].iov_len = %d\n", i*3+2, iov[i*3+2].iov_len);
    }
    /* We also need to free the iov itself in the callback */
    req->iov_to_free = iov;

    dbug("wait_for: %d\n", wait_for);

    result = globus_xio_driver_pass_write(op, (globus_xio_iovec_t *)iov,
        3 * iovec_count, wait_for, globus_l_xio_compression_write_cb, req);

    return result;
}

#if 1 // esjung
/*
 * Steps:
 * 1. Wait until nr_wait_worker=nr_thread.
 * 2. Reset nr_wait_worker.
 * 3. Fill bounce information.;not needed since already copied in compression_write()
 * 4. Wake up all worker threads.
 * 5. Wait until nr_finish_worker=nr_thread.
 * 6. Reset nr_finish_worker.
 * 7. if success 
 *		call globus_xio_driver_pass_write()
 *	  else
 *	    call globus_xio_driver_write()
 */
 
static
void
globus_l_xio_compression_thread_kicker(
    void *                              driver_specific_handle)
{
	int									i;
	int									nr_worker;
    globus_result_t                     result=GLOBUS_SUCCESS;

    xio_l_compression_driver_handle_t * driver_handle;

    driver_handle = (xio_l_compression_driver_handle_t *) driver_specific_handle;

   	dbug("globus_l_xio_compression_thread_kicker() called.\n");

	nr_worker = driver_handle->worker_thr.nr_thread;

	// 1. Wait until nr_wait_worker=nr_thread.
	globus_mutex_lock(&driver_handle->worker_thr.common_mutex);
	if (driver_handle->worker_thr.nr_wait_worker != nr_worker)
	{
   		dbug("globus_l_xio_compression_thread_kicker(): waiting for all_wait signal.\n");
		globus_cond_wait(&driver_handle->worker_thr.wait_cond, &driver_handle->worker_thr.common_mutex); 
	}
   	dbug("globus_l_xio_compression_thread_kicker(): received all_wait signal.\n");
	// 2. Reset nr_wait_worker.
	driver_handle->worker_thr.nr_wait_worker = 0;
	globus_mutex_unlock(&driver_handle->worker_thr.common_mutex);

	// 4. Wake up all worker threads.
	globus_mutex_lock(&driver_handle->worker_thr.common_mutex);
	driver_handle->worker_thr.nr_ready_worker++;
	dbug("thread_kicker(): nr_worker %d, nr_ready_worker %d\n", nr_worker, driver_handle->worker_thr.nr_ready_worker);
	if (driver_handle->worker_thr.nr_ready_worker == (nr_worker+1))
	{
		driver_handle->worker_thr.nr_ready_worker = 0;
		dbug("thread_kicker(): cond_broadcast\n"); 
		globus_cond_broadcast(&driver_handle->worker_thr.ready_cond);
	}
	else
		globus_cond_wait(&driver_handle->worker_thr.ready_cond, &driver_handle->worker_thr.common_mutex); // wait
	globus_mutex_unlock(&driver_handle->worker_thr.common_mutex);

   	dbug("globus_l_xio_compression_thread_kicker(): receive all ready signal.\n");

	// 5. Wait until nr_finish_worker=nr_thread.
	globus_mutex_lock(&driver_handle->worker_thr.common_mutex);
	if (driver_handle->worker_thr.nr_finish_worker != nr_worker)
		globus_cond_wait(&driver_handle->worker_thr.finish_cond, &driver_handle->worker_thr.common_mutex); 
   	dbug("globus_l_xio_compression_thread_kicker(): receive all finish signal.\n");
	// 6. Reset nr_finish_worker.
	driver_handle->worker_thr.nr_finish_worker = 0;
	globus_mutex_unlock(&driver_handle->worker_thr.common_mutex);

    if (result == GLOBUS_SUCCESS)
	{
		int wait_for=0;
		for (i=0; i<driver_handle->worker_thr.nr_thread; i++)
		{
			wait_for += driver_handle->worker_thr.pbounces[i].wait_for;
		}

   		dbug("globus_l_xio_compression_thread_kicker(): wait_for %d\n");

		// pass_write
		globus_xio_driver_pass_write(driver_handle->worker_thr.pbounces[0].op,
			driver_handle->worker_thr.pbounces[0].new_iovec,
			driver_handle->worker_thr.pbounces[0].new_iovec_count,
			wait_for,
			globus_l_xio_compression_write_cb,
			driver_handle->worker_thr.pbounces[0].req);
	}
	else
    {
        globus_xio_driver_finished_write(driver_handle->worker_thr.pbounces[0].op, result, 0);
    }

}

#else

static
void
globus_l_xio_compression_thread_kicker(
    void *                              user_arg)
{
    globus_result_t                     result;

    globus_l_xio_compression_bounce_t * bounce;

    bounce = (globus_l_xio_compression_bounce_t *) user_arg;

    result = globus_l_xio_compression_fake_write(
        bounce->driver_handle,
        bounce->iovec,
        bounce->iovec_count,
        bounce->op);
    if(result != GLOBUS_SUCCESS)
    {
        globus_xio_driver_finished_write(bounce->op, result, 0);
    }

    globus_free(bounce->iovec);
    globus_free(bounce);
}

#endif


/*
 * Initialize bounce structures for each worker threads.
 * - set original iovec, iovec_count
 * - set new iovec, iovec_count
 * - set req
 */
static
globus_result_t
globus_l_xio_compression_write(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    int                                 i;
#if 1 // esjung
    int                                 w, new_iovec_count;
	globus_xio_iovec_t *				new_iovec;
	xio_l_compression_req_t *			req;

	dbug("################### iovec_count: %d\n", iovec_count);
    globus_l_xio_compression_bounce_t * pbounces =
        ((xio_l_compression_driver_handle_t *)driver_specific_handle)->worker_thr.pbounces;

	// allocate new_iovec, new_iovec_count
	new_iovec_count = 3 * iovec_count;
	new_iovec = (globus_xio_iovec_t *) globus_calloc(new_iovec_count, sizeof(globus_xio_iovec_t));

	// allocate req
	req = globus_calloc(sizeof(xio_l_compression_req_t), 1);
	req->buffers_to_free = (globus_xio_iovec_t *) globus_calloc(1+3*iovec_count, sizeof(globus_xio_iovec_t));

    // set iovec, iovec_count
    for (w=0; w<((xio_l_compression_driver_handle_t *)driver_specific_handle)->worker_thr.nr_thread; w++ )
    {
        pbounces[w].op = op;
        pbounces[w].iovec_count = iovec_count;
        pbounces[w].iovec = iovec;
        pbounces[w].new_iovec_count = new_iovec_count;
        pbounces[w].new_iovec = new_iovec;
        pbounces[w].req = req;
        pbounces[w].wait_for = 0;
    }

    globus_callback_register_oneshot(
        NULL,
        NULL,
        globus_l_xio_compression_thread_kicker,
        driver_specific_handle);
#else
    globus_l_xio_compression_bounce_t * bounce;

    bounce = globus_calloc(1, sizeof(globus_l_xio_compression_bounce_t));
    bounce->driver_specific_handle = driver_specific_handle;
    bounce->op = op;
    bounce->iovec_count = iovec_count;
    bounce->iovec = globus_calloc(iovec_count, sizeof(globus_xio_iovec_t));

    for(i = 0; i < iovec_count; i++)
    {
        bounce->iovec[i].iov_base = iovec[i].iov_base;
        bounce->iovec[i].iov_len = iovec[i].iov_len;
    }

    globus_callback_register_oneshot(
        NULL,
        NULL,
        globus_l_xio_compression_thread_kicker,
        bounce);
#endif

    return GLOBUS_SUCCESS;
}


static
globus_result_t
globus_l_xio_compression_handle_write(
    globus_xio_iovec_t *                header_dest,
    globus_xio_iovec_t *                payload_dest,
    const globus_xio_iovec_t *          source) 
{
    globus_byte_t *                     header_buffer;
    int                                	header_index;
    static globus_byte_t                compression_strategy;
    uint32_t                            buffer_len;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_compression_handle_write);

    /* TODO: only set strategy for the first block transfer */
    compression_strategy = 
        globus_l_xio_compression_set_strategy((globus_xio_iovec_t *)source);

    switch (compression_strategy)
    {
        case NO_COMPRESSION_MEMCPY :
            result = globus_l_xio_compression_handle_write_no_compression(
                payload_dest, source, NO_COMPRESSION_MEMCPY);
            dbug("Strategy NO_COMPRESSION_MEMCPY used\n");
            break;
        case NO_COMPRESSION_POINTERS :
            result = globus_l_xio_compression_handle_write_no_compression(
                payload_dest, source, NO_COMPRESSION_POINTERS);
            dbug("Strategy NO_COMPRESSION_POINTERS used\n");
            break;
        case LZO_DEFAULT_COMPRESSION :
            result = globus_l_xio_compression_handle_write_lzo(
                payload_dest, source);
            dbug("Strategy LZO_DEFAULT_COMPRESSION used\n");
            break;
        case ZLIB_DEFAULT_COMPRESSION :
            result = globus_l_xio_compression_handle_write_zlib(
                payload_dest, source, 9); // 9: highest compression level in blosc
            break;
        default :
            ;
            result = GlobusXIOCompressionError(
                "compression strategy not recognized");
            return result;
    }
            
    /* Create the header. */ 
    header_buffer = globus_malloc(HEADER_LEN);
    header_index = 0;

    header_buffer[header_index] = compression_strategy;
    header_index++;
    buffer_len = htonl(source->iov_len);
    memcpy(&header_buffer[header_index], &buffer_len, sizeof(buffer_len));
    header_index += sizeof(buffer_len);
    dbug("sending compressed len of %d\n", buffer_len);

    header_dest->iov_base = header_buffer;
    header_dest->iov_len = HEADER_LEN;

	dbug("source len: %d\n", source->iov_len);
    dbug("header_dest len: %d\n", header_dest->iov_len);
	dbug("payload_dest len: %d\n", payload_dest->iov_len);

    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_compression_handle_write_no_compression(
    globus_xio_iovec_t *                dest,
    const globus_xio_iovec_t *          source,
    globus_byte_t                       flag)

{
    if (flag == NO_COMPRESSION_POINTERS)
    {
        dest->iov_base = source->iov_base;
        dest->iov_len = source->iov_len;
    }
    else if (flag == NO_COMPRESSION_MEMCPY)
    {
        dest->iov_base = globus_malloc(source->iov_len);
        dest->iov_len = source->iov_len;
        memcpy(dest->iov_base, source->iov_base, source->iov_len);
    }
    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_compression_handle_write_lzo(
    globus_xio_iovec_t *                dest,
    const globus_xio_iovec_t *          source)
{
    GlobusXIOName(globus_l_xio_compression_handle_write_lzo);

#   if defined(HAVE_LIBLZO)
    {
        lzo_bytep                       wrkmem;
        globus_size_t                   max_compressed_len;
        int                            	lzo_result;
        globus_result_t                 globus_result;

        /* This value for max_compressed_len seems a bit large... Taken from
         * blockz-driver.
        * TODO: check lzo docs if this is really necessary... */
        max_compressed_len = source->iov_len + source->iov_len / 16 + 64 + 3;
        dest->iov_base = globus_calloc(1, max_compressed_len);

        wrkmem = (lzo_bytep) lzo_malloc(LZO1X_1_MEM_COMPRESS);

        lzo_result = lzo1x_1_compress(
            (const lzo_bytep) source->iov_base,
            (lzo_uint) source->iov_len,
            (lzo_bytep) dest->iov_base,
            (lzo_uintp) &dest->iov_len,
            wrkmem);

        lzo_free(wrkmem);

        if(lzo_result != LZO_E_OK)
        {
            globus_result = GlobusXIOCompressionError(
                "lzo compression failed");
            return globus_result;
        }
    }
#   else
    {
        return GlobusXIOCompressionError("no lzo");
    }
#   endif

    return GLOBUS_SUCCESS;
}

#if 1

static
globus_result_t
globus_l_xio_compression_handle_write_zlib(
    globus_xio_iovec_t *                dest,
    const globus_xio_iovec_t *          source,
    globus_byte_t                       level)
{
    GlobusXIOName(globus_l_xio_compression_handle_write_zlib);

	dbug("globus_l_xio_compression_handle_write_blosc() called.\n");

    {
        globus_size_t                   max_compressed_len;
        uLongf                          compressed_len;
        globus_size_t                   uncompressed_len;
        globus_result_t                 globus_result;

        uncompressed_len = source->iov_len;

        /* The compressed buffer can under certain circumstances be 
            slightly longer than the uncompressed buffer. Therefore: */
        max_compressed_len = source->iov_len + BLOSC_MAX_OVERHEAD; 
        dest->iov_base = globus_calloc(1, max_compressed_len);
        if (dest->iov_base == NULL)
        {
			dbug("memory alloc error.\n");
            globus_result = GlobusXIOCompressionError("blosc compression failed");
            return globus_result;
        }

        /* Compress */
        uncompressed_len = source->iov_len;
        compressed_len = blosc_compress(
			level, // compress level
			1, // shuffle
			8, // typesize affecting shuffle
			uncompressed_len, // source size	
            (const void *) source->iov_base, // source
            (void *) dest->iov_base,  // dest
            max_compressed_len); 
        dbug("BLOSC compress result JB: %ld\n", compressed_len);
		dest->iov_len = compressed_len;

        if (compressed_len <= 0)
        {
            globus_result = GlobusXIOCompressionError("blosc compression failed");
            return globus_result;
        }
    }

    return GLOBUS_SUCCESS;
}

#else

static
globus_result_t
globus_l_xio_compression_handle_write_zlib(
    globus_xio_iovec_t *                dest,
    const globus_xio_iovec_t *          source,
    globus_byte_t                       level)
{
    GlobusXIOName(globus_l_xio_compression_handle_write_zlib);

	dbug("globus_l_xio_compression_handle_write_zlib() called.\n");

#   if(HAVE_LIBZ)
    {
        globus_size_t                   max_compressed_len;
        uLongf                          compressed_len;
        globus_size_t                   uncompressed_len;
        int                            	zlib_result;
        globus_result_t                 globus_result;

        uncompressed_len = source->iov_len;

        /* The compressed buffer can under certain circumstances be 
            slightly longer than the uncompressed buffer. Therefore: */
        max_compressed_len = source->iov_len + source->iov_len / 1000 + 12; 
        dest->iov_base = globus_calloc(1, max_compressed_len);
        compressed_len = max_compressed_len;
        /* Compress */
        uncompressed_len = source->iov_len;
        zlib_result = compress(
            (Byte *) dest->iov_base, 
            (uLong *) &compressed_len, 
            (Byte *) source->iov_base,
            (uLong) uncompressed_len);
        dbug("compress result JB: %ld\n", compressed_len);
	dest->iov_len = compressed_len;

        if (zlib_result != Z_OK)
        {
            globus_result = GlobusXIOCompressionError(
                "zlib compression failed");
            return globus_result;
        }
    }
#   else
    {
        return GlobusXIOCompressionError("no zlib");
    }
#   endif
    return GLOBUS_SUCCESS;
}

#endif

static
void
globus_l_xio_compression_write_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    xio_l_compression_req_t *            req;
    int                                 i = 0;

    dbug("globus_l_xio_compression_write_cb() called\n");

    req = (xio_l_compression_req_t *) user_arg;
    
    while (req->buffers_to_free[i].iov_base != NULL)
    {
        globus_free(req->buffers_to_free[i].iov_base);
        i++;
    }
    /* Note the last argument of the call to finished_write() - we need
     * to notify XIO how much data we have "taken care of", in this
     * case the size of the buffer before compression. */
    globus_xio_driver_finished_write(op, result, req->original_size);
    globus_free(req->iov_to_free);
    globus_free(req->buffers_to_free);
    globus_free(req);
}

static
globus_byte_t
globus_l_xio_compression_set_strategy (globus_xio_iovec_t * iovec) 
{
    /*TODO: determine compression strategy dynamically. For example,
     * do a test-compression of iovec using all available strategies and
     * chose the one which gives the best ration. This should probably
     * only be done once each transfer - if the first block compresses
     * nicely, we can probably assume that the rest will also*/

#   if defined(HAVE_LIBLZO)
    {
        return LZO_DEFAULT_COMPRESSION;
    }
#   elif defined(HAVE_LIBZ)
    {
        return ZLIB_DEFAULT_COMPRESSION;
    }
#   else
    {
        return NO_COMPRESSION_MEMCPY;
    }
#   endif
}
