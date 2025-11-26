import { useCallback, useState } from 'react';
import { useDropzone } from 'react-dropzone';
import { Upload, FileWarning, Loader2, Smartphone } from 'lucide-react';
import { uploadApk } from '@/lib/api';
import { cn, formatBytes } from '@/lib/utils';

interface FileUploadProps {
  onUploadSuccess: (reportId: number) => void;
}

export default function FileUpload({ onUploadSuccess }: FileUploadProps) {
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [uploadedFile, setUploadedFile] = useState<File | null>(null);

  const getFileType = (fileName: string): 'apk' | 'ipa' | null => {
    const lower = fileName.toLowerCase();
    if (lower.endsWith('.apk')) return 'apk';
    if (lower.endsWith('.ipa')) return 'ipa';
    return null;
  };

  const onDrop = useCallback(
    async (acceptedFiles: File[]) => {
      const file = acceptedFiles[0];
      if (!file) return;

      // Validate file extension
      const fileType = getFileType(file.name);
      if (!fileType) {
        setError('Only APK (Android) and IPA (iOS) files are allowed');
        return;
      }

      // Validate file size (500MB max)
      if (file.size > 500 * 1024 * 1024) {
        setError('File size exceeds 500MB limit');
        return;
      }

      setError(null);
      setUploadedFile(file);
      setUploading(true);

      try {
        const response = await uploadApk(file);
        onUploadSuccess(response.report_id);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Upload failed');
        setUploadedFile(null);
      } finally {
        setUploading(false);
      }
    },
    [onUploadSuccess]
  );

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'application/vnd.android.package-archive': ['.apk'],
      'application/octet-stream': ['.ipa'],
    },
    maxFiles: 1,
    disabled: uploading,
  });

  return (
    <div className="w-full">
      <div
        {...getRootProps()}
        className={cn(
          'border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-colors',
          isDragActive
            ? 'border-blue-500 bg-blue-50'
            : 'border-gray-300 hover:border-gray-400 hover:bg-gray-50',
          uploading && 'cursor-not-allowed opacity-60'
        )}
      >
        <input {...getInputProps()} />

        {uploading ? (
          <div className="flex flex-col items-center space-y-4">
            <Loader2 className="h-12 w-12 text-blue-500 animate-spin" />
            <div>
              <p className="text-lg font-medium text-gray-900">
                Uploading {uploadedFile?.name}
              </p>
              <p className="text-sm text-gray-500">
                {uploadedFile && formatBytes(uploadedFile.size)}
              </p>
            </div>
          </div>
        ) : (
          <div className="flex flex-col items-center space-y-4">
            <div className="flex items-center space-x-2">
              <Upload className="h-12 w-12 text-gray-400" />
              <Smartphone className="h-10 w-10 text-gray-400" />
            </div>
            <div>
              <p className="text-lg font-medium text-gray-900">
                {isDragActive
                  ? 'Drop the mobile app here'
                  : 'Drag & drop a mobile app file'}
              </p>
              <p className="text-sm text-gray-500">
                APK (Android) or IPA (iOS) files supported (max 500MB)
              </p>
              <div className="flex justify-center space-x-4 mt-2">
                <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300">
                  Android APK
                </span>
                <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300">
                  iOS IPA
                </span>
              </div>
            </div>
          </div>
        )}
      </div>

      {error && (
        <div className="mt-4 p-4 bg-red-50 border border-red-200 rounded-lg flex items-center space-x-2">
          <FileWarning className="h-5 w-5 text-red-500" />
          <p className="text-sm text-red-700">{error}</p>
        </div>
      )}
    </div>
  );
}
