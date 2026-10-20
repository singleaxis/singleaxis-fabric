# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""LlamaIndex ``FunctionAgent`` over ``OpenAILike`` (``api_base``); ``--variant rag`` is a
VectorStoreIndex RAG pipeline (OpenAI-compatible embeddings + chat)."""

from __future__ import annotations

import asyncio
import os

import _common as c
from llama_index.core import Document, Settings, VectorStoreIndex
from llama_index.core.agent.workflow import FunctionAgent
from llama_index.core.base.llms.types import ChatMessage, ImageBlock, TextBlock
from llama_index.core.tools import FunctionTool
from llama_index.llms.openai_like import OpenAILike

ns = c.args()
KEY = os.environ["OPENAI_API_KEY"]


def llm() -> OpenAILike:
    return OpenAILike(model=ns.model, api_base=ns.openai_base, api_key=KEY, is_chat_model=True,
                      is_function_calling_model=True, context_window=128000, max_retries=2)


async def agent() -> str:
    tools = [FunctionTool.from_defaults(fn=c.get_weather), FunctionTool.from_defaults(fn=c.c_to_f)]
    worker = FunctionAgent(tools=tools, llm=llm(), streaming=ns.stream,
                           system_prompt="Answer weather questions with the tools.")
    msg: object = c.prompt()
    if ns.image:
        msg = ChatMessage(role="user", blocks=[TextBlock(text=c.prompt())] + [
            ImageBlock(image=png, image_mimetype="image/png") for png in c.images()])
    handler = worker.run(user_msg=msg, max_iterations=c.MAX_STEPS)
    async for _ in handler.stream_events():
        pass
    return str(await handler)


def rag() -> str:
    from llama_index.embeddings.openai_like import OpenAILikeEmbedding

    Settings.llm = llm()
    Settings.embed_model = OpenAILikeEmbedding(model_name="fm-embed", api_base=ns.openai_base,
                                               api_key=KEY, embed_batch_size=4)
    docs = [Document(text=f"Station report {i}: Paris is 18.5 C; Lyon is {10 + i} C. "
                          f"{c.secret()}") for i in range(6)]
    index = VectorStoreIndex.from_documents(docs)
    engine = index.as_query_engine(similarity_top_k=2, streaming=ns.stream)
    queries = 24 if ns.scenario == "long50" else 1
    answers = []
    for i in range(queries):
        response = engine.query(c.prompt(f" (query {i})"))
        answers.append(str(response.get_response() if ns.stream else response)
                       if not ns.stream else "".join(response.response_gen))
    return "\n".join(answers)


c.run(ns.out, rag if ns.variant == "rag" else lambda: asyncio.run(agent()))
