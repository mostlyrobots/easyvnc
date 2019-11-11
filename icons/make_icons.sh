
rm -r EasyVNC.iconset*
mkdir -p EasyVNC.iconset

convert _originals/VNC.png -resize   16 EasyVNC.iconset/icon_16x16.png
convert _originals/VNC.png -resize   32 EasyVNC.iconset/icon_16x16@2x.png
convert _originals/VNC.png -resize   32 EasyVNC.iconset/icon_32x32.png
convert _originals/VNC.png -resize   64 EasyVNC.iconset/icon_32x32@2x.png
convert _originals/VNC.png -resize  128 EasyVNC.iconset/icon_128x128.png
convert _originals/VNC.png -resize  256 EasyVNC.iconset/icon_128x128@2x.png
convert _originals/VNC.png -resize  256 EasyVNC.iconset/icon_256x256.png
convert _originals/VNC.png -resize  512 EasyVNC.iconset/icon_256x256@2x.png
convert _originals/VNC.png -resize  512 EasyVNC.iconset/icon_512x512.png
convert _originals/VNC.png -resize 1024 EasyVNC.iconset/icon_512x512@2x.png

iconutil -c icns EasyVNC.iconset

convert EasyVNC.iconset/icon_16x16.png EasyVNC.iconset/icon_32x32.png EasyVNC.iconset/icon_128x128.png EasyVNC.iconset/icon_256x256.png EasyVNC.iconset/icon_512x512.png EasyVNC.ico
