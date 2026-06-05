using System;
using System.Diagnostics;

namespace FNS_rebuild
{
    internal sealed class Crypto_operation_timing
    {
        readonly Stopwatch wrapper_stopwatch = new();
        readonly Stopwatch core_stopwatch = new();

        internal TimeSpan Wrapper_elapsed => wrapper_stopwatch.Elapsed;
        internal TimeSpan Core_elapsed => core_stopwatch.Elapsed;

        internal void Start_wrapper()
        {
            if (!wrapper_stopwatch.IsRunning)
                wrapper_stopwatch.Start();
        }

        internal void Stop_wrapper()
        {
            if (wrapper_stopwatch.IsRunning)
                wrapper_stopwatch.Stop();
        }

        internal T Measure_core<T>(Func<T> action)
        {
            ArgumentNullException.ThrowIfNull(action);

            bool resume_wrapper = wrapper_stopwatch.IsRunning;
            if (resume_wrapper)
                wrapper_stopwatch.Stop();

            core_stopwatch.Start();
            try
            {
                return action();
            }
            finally
            {
                core_stopwatch.Stop();
                if (resume_wrapper)
                    wrapper_stopwatch.Start();
            }
        }
    }
}
