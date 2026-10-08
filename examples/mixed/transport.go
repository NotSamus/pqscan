package transport

import "crypto/tls"

// A hybrid preference with classical fallback still needs deployment review.
var config = tls.Config{
    CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
}
