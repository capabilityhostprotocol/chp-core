"""chp-adapter-jobs — run any CHP capability as a polled background job.

submit(capability_id, payload) returns a job_id immediately and runs the target
via host.ainvoke in a thread pool; poll status and fetch result. For heavy or
long-running capabilities (e.g. huggingface.generate_image) that outlive HTTP
request timeouts. The target keeps its own evidence chain.

Usage::

    from chp_core import LocalCapabilityHost, register_adapter
    from chp_adapter_jobs import JobsAdapter, JobsConfig

    host = LocalCapabilityHost()
    register_adapter(host, JobsAdapter(JobsConfig()))
    job = host.invoke("chp.adapters.jobs.submit", {
        "capability_id": "chp.adapters.huggingface.generate_image",
        "payload": {"prompt": "...", "output_path": "/tmp/out.png"},
    })
"""

from __future__ import annotations

from .adapter import JobsAdapter, JobsConfig

__all__ = ["JobsAdapter", "JobsConfig"]
