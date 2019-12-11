
// qrcode.c

#include "global.h"
#include "qrencode.h"
#include "lodepng.h"

enum {
	PIXELS_PER_CELL =4,
	QUIET_ZONE_SIZE =2*PIXELS_PER_CELL
};
	
/*
===============================================================================
	SEND STRING AS QR CODE IMAGE
	in:  pszStringToConvert
	in:  pSCB
===============================================================================
*/
// The string to convert is of the form 
//  "sqrl://nut=<base64url nut>&cps=<base64url URL>"
// First we encode it into a QR code
// Then create an image with a quiet zone around it
// And finally send back the QR image in PNG format

void SendStringAsQRcodeImage(SQRL_CONTROL_BLOCK *pSCB, SQ_CHAR *pszStringToConvert) {
	BEG("SendStringAsQRcodeImage()");

	// Encode the string into a QR Code
	QRcode *pQRcode=QRcode_encodeString8bit(pszStringToConvert, 0, QR_ECLEVEL_L);
	
	// QRcodes are square
	// For clarity we use separate variables for width and height
	int QRwidth=pQRcode->width;
	int QRheight=QRwidth;
	int zone=QUIET_ZONE_SIZE;
	int scale=PIXELS_PER_CELL;

	// The data is one byte per cell
	// Bit 0 indicates black(1) or white(0)
	// The code is scaled by the factor PIXELS_PER CELL
	// It is surrounded by a zone of QUIET_ZONE_SIZE pixels (already scaled)
	
	// The image width and height include two zones
	int IMwidth=QRwidth*scale+2*zone;
	int IMheight=QRheight*scale+2*zone;
	
	// Allocate memory for the image
	int IMarea=IMwidth*IMheight;
	unsigned char *pImage=(unsigned char *)GlobalAlloc(IMarea);

	// Initialize the image to all white
	memset(pImage, 0xff, IMarea);

	// Center the QR code by starting the image ndx at row=zone, col=zone
	int row, col, srow, scol;
	int ndx=zone*IMwidth+zone;
	
	// Start the cell pointer at the  QR data
	unsigned char *pQRcell=pQRcode->data;
	
	// Loop through the QRcode cell by cell
	for(row=zone; row<zone+QRheight; row++) {
		for(col=zone; col<zone+QRwidth; col++) {
			if((*pQRcell&0x01)==0x01){
				// Insert a block of pixels
				for(srow=0; srow<scale; srow++)
				for(scol=0; scol<scale; scol++)
				pImage[ndx+srow*IMwidth+scol]=0x00;
			}
			// next QR column
			pQRcell++;
			ndx+=scale;
		}
		// next QR row
		ndx+=(IMwidth-QRwidth)*scale;
	}

	int colortype=LCT_GREY;
	int bitdepth=8;
	unsigned char *pQRpng;
	size_t QRpngSize;
	lodepng_encode_memory(&pQRpng, &QRpngSize, pImage, IMwidth, IMheight, colortype, bitdepth);

//[ For testing, save it to a file
	LOG("Output size: %d", QRpngSize);
	FILE *pFile=fopen("QRcode.png", "w");
	if(pFile==NULL) {
		LOG("Error: %s, %d", __FILE__, __LINE__);
	}
	else {
		fwrite(pQRpng, 1, QRpngSize, pFile);
	}
	if(pFile!=NULL) {
		fflush(pFile);
		fclose(pFile);
	}
//]
	ReturnImageToClient(pSCB, pQRpng, QRpngSize);

	// Release all the allocated memory
	free(pQRpng); // (allocated by lodepng)
	GlobalFree((void **)&pImage);
	QRcode_free(pQRcode);

	END();
}
