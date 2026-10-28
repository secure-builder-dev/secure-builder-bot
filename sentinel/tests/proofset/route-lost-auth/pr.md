# Simplify the notes routes

Removes the duplicated middleware from the single-note route; the router already
authenticates every request, and the service reads the note directly.
