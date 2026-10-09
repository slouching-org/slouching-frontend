# Native asset sources

Art, avatars, and brand images are byte-for-byte copies of the supplied
sources retained under `prototypes/web/`. They are used by native Iced widgets.
The frog, gnome, walking-wizard pair, and sleeping-mushroom cutouts were extracted without modification
from the home screen's embedded resources in the owner-supplied
`slouching-telas.html` preserved in the project repository. Outline SVG
paths were extracted from that same board; only SVG namespace, viewBox,
and intrinsic size attributes were normalized for standalone rendering.
These source-derived assets do not add an external icon library.

Bricolage Grotesque and JetBrains Mono variable TTF fonts were downloaded
from their official Google Fonts directories, with the corresponding SIL
Open Font License texts included alongside them:

- https://github.com/google/fonts/tree/main/ofl/bricolagegrotesque
- https://github.com/google/fonts/tree/main/ofl/jetbrainsmono

The supplied art and source-board icon provenance must still be reviewed
before a public product release. Originals are preserved in the design bank.
