## Purpose

Each Crowdsec connection’s cache Client has an isolated key space so two **sessions** in one process cannot read or write each other’s remediations or stream lease. Stream/alone middlewares that share a LAPI session share one Client (one prefix).
