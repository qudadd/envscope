"""Render the original EnvScope geometric mark for Windows/macOS packaging."""
from pathlib import Path
from PIL import Image, ImageDraw


def mark(size, *, tray=False):
    scale=4;canvas=Image.new('RGBA',(size*scale,size*scale),(0,0,0,0));draw=ImageDraw.Draw(canvas)
    def points(items):return [(round(x*size*scale/64),round(y*size*scale/64)) for x,y in items]
    ink='#202322';paper='#ffffff';line=paper
    if tray:
        draw.rounded_rectangle((2*scale,2*scale,(size-2)*scale,(size-2)*scale),radius=size*scale*.22,fill=paper,outline=ink,width=max(1,round(size*scale*.03)));line=ink
    else:draw.rounded_rectangle((0,0,size*scale-1,size*scale-1),radius=size*scale*15/64,fill=ink)
    for path in [[(26,16),(16,16),(16,26)],[(38,16),(48,16),(48,26)],[(16,38),(16,48),(26,48)],[(48,38),(48,48),(38,48)],[(25,32),(39,32)],[(32,25),(32,39)]]:
        draw.line(points(path),fill=line,width=max(1,round(size*scale*3.5/64)),joint='curve')
    return canvas.resize((size,size),Image.Resampling.LANCZOS)


def main():
    root=Path(__file__).resolve().parents[1]/'envscope/web';image=mark(1024)
    image.save(root/'app-icon.png',optimize=True)
    image.save(root/'app.ico',format='ICO',sizes=[(n,n) for n in (16,20,24,32,40,48,64,128,256)])
    image.save(root/'app.icns',format='ICNS')
    mark(64,tray=True).save(root/'tray.png',optimize=True)
    print('Original application, Windows, macOS and tray icons rendered.')


if __name__=='__main__':main()
