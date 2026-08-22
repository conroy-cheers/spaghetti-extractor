#include "portable-component-implementation.h"

enum gnu_hello_quoting_route {
  GNU_HELLO_QUOTING_ROUTE_DEFAULT = 0,
  GNU_HELLO_QUOTING_ROUTE_ESCAPE_PAIR = 1,
  GNU_HELLO_QUOTING_ROUTE_FORM_FEED = 2,
  GNU_HELLO_QUOTING_ROUTE_BACKSPACE = 3,
  GNU_HELLO_QUOTING_ROUTE_VERTICAL_TAB = 4,
  GNU_HELLO_QUOTING_ROUTE_NUL = 5,
  GNU_HELLO_QUOTING_ROUTE_HORIZONTAL_TAB = 6,
  GNU_HELLO_QUOTING_ROUTE_CARRIAGE_RETURN = 7,
  GNU_HELLO_QUOTING_ROUTE_LINE_FEED = 8,
  GNU_HELLO_QUOTING_ROUTE_SPACE = 9,
  GNU_HELLO_QUOTING_ROUTE_HASH = 10,
  GNU_HELLO_QUOTING_ROUTE_BELL = 11
};

uint32_t gnu_hello_finite_selector_dispatch(
    spx_finite_selector_dispatch_context_v2 *context,
    uint8_t selector) {
  (void)context;
  switch (selector) {
    case 0:
      return GNU_HELLO_QUOTING_ROUTE_NUL;
    case 7:
      return GNU_HELLO_QUOTING_ROUTE_BELL;
    case 8:
      return GNU_HELLO_QUOTING_ROUTE_BACKSPACE;
    case 9:
      return GNU_HELLO_QUOTING_ROUTE_HORIZONTAL_TAB;
    case 10:
      return GNU_HELLO_QUOTING_ROUTE_LINE_FEED;
    case 11:
      return GNU_HELLO_QUOTING_ROUTE_VERTICAL_TAB;
    case 12:
      return GNU_HELLO_QUOTING_ROUTE_FORM_FEED;
    case 13:
      return GNU_HELLO_QUOTING_ROUTE_CARRIAGE_RETURN;
    case 32:
      return GNU_HELLO_QUOTING_ROUTE_SPACE;
    case 33:
    case 34:
      return GNU_HELLO_QUOTING_ROUTE_ESCAPE_PAIR;
    case 35:
      return GNU_HELLO_QUOTING_ROUTE_HASH;
    default:
      return GNU_HELLO_QUOTING_ROUTE_DEFAULT;
  }
}
