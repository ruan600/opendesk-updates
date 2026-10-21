# Only relay sources are admitted by .dockerignore.
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /source
COPY src/OpenDesk.Relay/OpenDesk.Relay.csproj src/OpenDesk.Relay/
RUN dotnet restore src/OpenDesk.Relay/OpenDesk.Relay.csproj
COPY src/OpenDesk.Relay/Program.cs src/OpenDesk.Relay/
RUN dotnet publish src/OpenDesk.Relay/OpenDesk.Relay.csproj -c Release --no-restore -o /app/publish /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
COPY --from=build /app/publish ./
ENV ASPNETCORE_URLS=http://0.0.0.0:10000
ENV DOTNET_EnableDiagnostics=0
EXPOSE 10000
USER $APP_UID
ENTRYPOINT ["dotnet", "OpenDesk.Relay.dll"]
