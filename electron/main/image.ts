import { nativeImage } from "electron";

export function getRealImageData(filePath: string){
    try {
      const image = nativeImage.createFromPath(filePath);
      if (image.isEmpty()) throw new Error('Invalid image');
      return image.toDataURL();
    } catch (err) {
      console.error('Failed to load image:', err);
      return null;
    }
}