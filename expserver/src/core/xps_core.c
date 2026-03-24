#include "../xps.h"
xps_core_t *xps_core_create() {

  xps_core_t *core = malloc(sizeof(xps_core_t));/* allocate memory using malloc() */
  /* handle error where core == NULL */
  if(core == NULL) {
    logger(LOG_ERROR, "xps_core_create()", "malloc() failed for 'core'");
    return NULL;
  }

  xps_loop_t *loop = xps_loop_create(core); /* create xps_loop instance */
  /* handle error where loop == NULL */
  if(loop == NULL) {
    logger(LOG_ERROR, "xps_core_create()", "malloc() failed for 'loop'");
    free(core);
    return NULL;
  }

  // Init values
  core->loop = loop;/* fill this */
  vec_init(&core->listeners);/* initialize core->listeners */
  /* initialize core->connections */
  vec_init(&core->connections);/* fill this */
  core->n_null_listeners = 0;
  /* initialize core->n_null_connections */
  core->n_null_connections = 0;/* fill this */

  logger(LOG_DEBUG, "xps_core_create()", "created core");

  return core;
}

void xps_core_destroy(xps_core_t *core) {
  /* validate params */
  assert(core != NULL);
  logger(LOG_DEBUG, "xps_core_destroy()", "destroying core");
  // Destroy connections
  for (int i = 0; i < core->connections.length; i++) {
    xps_connection_t *connection = core->connections.data[i];
    if (connection != NULL)
    xps_connection_destroy(connection); // modification of xps_connection_destroy() will be look at later
  }
  vec_deinit(&(core->connections));
  logger(LOG_DEBUG, "xps_core_destroy()", "destroyed connections");
  
  /* destory all the listeners and de-initialize core->listeners */
  for (int i = 0; i < core->listeners.length; i++) {
    xps_listener_t *listener = core->listeners.data[i];
    logger(LOG_DEBUG, "xps_core_destroy()", "destroying listener on port %d", ((xps_listener_t *)core->listeners.data[i])->port);
    if (listener != NULL)
    xps_listener_destroy(listener); // modification of xps_listener_destroy() will be look at later
  }
  vec_deinit(&(core->listeners));
  logger(LOG_DEBUG, "xps_core_destroy()", "destroyed listeners");

  /* destory loop attached to core */
  xps_loop_destroy(core->loop);
  logger(LOG_DEBUG, "xps_core_destroy()", "destroyed loop");

  /* free core instance */
  free(core);

  logger(LOG_DEBUG, "xps_core_destroy()", "destroyed core");
}

void xps_core_start(xps_core_t *core) {

  /* validate params */
  assert(core != NULL);


  /* create listeners from port 8001 to 8004 */
  for (u_int i=8001; i<=8004; i++) {
    xps_listener_t *listener = xps_listener_create(core, "0.0.0.0", i);
    if (listener == NULL) {
      logger(LOG_ERROR, "xps_core_start()", "xps_listener_create() failed for port %u", i);
      return;
    }
  }

  /* run loop instance using xps_loop_run() */
  xps_loop_run(core->loop);

}