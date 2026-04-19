using Pulsar.Common.Models;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;

namespace Pulsar.Common.IO
{
    public class FileSplit : IEnumerable<FileChunk>, IDisposable
    {
        public readonly int MaxChunkSize = 65535;

        public string FilePath => _fileStream.Name;
        public long FileSize => _fileStream.Length;

        public long BytesWritten { get; private set; }

        private readonly FileStream _fileStream;
        private readonly bool _keepOpen;
        private bool _disposed;

        public FileSplit(string filePath, FileAccess fileAccess, bool keepOpen = false)
        {
            _keepOpen = keepOpen;

            switch (fileAccess)
            {
                case FileAccess.Read:
                    _fileStream = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    break;

                case FileAccess.Write:
                    var dir = Path.GetDirectoryName(filePath);
                    if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                        Directory.CreateDirectory(dir);
                    _fileStream = File.Open(filePath, FileMode.Create, FileAccess.Write, FileShare.ReadWrite);
                    BytesWritten = 0;
                    break;

                default:
                    throw new ArgumentException($"{nameof(fileAccess)} must be either Read or Write.");
            }
        }

        public void WriteChunk(FileChunk chunk)
        {
            _fileStream.Seek(chunk.Offset, SeekOrigin.Begin);
            _fileStream.Write(chunk.Data, 0, chunk.Data.Length);
            BytesWritten += chunk.Data.Length;
        }

        public void Flush()
        {
            _fileStream.Flush(true);
        }

        public bool VerifyFileComplete(long expectedSize)
        {
            Flush();
            return BytesWritten == expectedSize && _fileStream.Length == expectedSize;
        }

        public FileChunk ReadChunk(long offset)
        {
            _fileStream.Seek(offset, SeekOrigin.Begin);

            long remaining = _fileStream.Length - _fileStream.Position;
            long chunkSize = remaining < MaxChunkSize ? remaining : MaxChunkSize;

            var buffer = new byte[chunkSize];
            int read = _fileStream.Read(buffer, 0, buffer.Length);

            if (read < buffer.Length)
                Array.Resize(ref buffer, read);

            return new FileChunk
            {
                Data = buffer,
                Offset = _fileStream.Position - read
            };
        }

        public IEnumerator<FileChunk> GetEnumerator()
        {
            for (long offset = 0; offset < _fileStream.Length; offset += MaxChunkSize)
                yield return ReadChunk(offset);
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

        protected virtual void Dispose(bool disposing)
        {
            if (!disposing || _disposed)
                return;

            _disposed = true;

            if (_keepOpen)
                return; // DO NOT close file if handler controls lifecycle

            try { _fileStream.Flush(true); } catch { }
            _fileStream.Dispose();
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}
